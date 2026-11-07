use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use std::collections::{BTreeMap, HashMap};
type HmacSha256 = Hmac<Sha256>;

pub const KINDS: &[&str] = &["github","gitlab","vercel","netlify","cloudflare","cloudflare_pages","trigger","supabase","nomad","coolify","aws_secrets_manager","aws_parameter_store","gcp_secret_manager","azure_key_vault","azure_app_configuration","digitalocean","railway","render","flyio","heroku","kubernetes","hashicorp_vault","webhook","instabox","boat","daytona","1password","dokploy","caprover","portainer","docker_swarm","bitbucket","circleci","teamcity","travisci","terraform_cloud","qovery","laravel_forge","openwarp","devin","cloudflare_secrets_store","octopus_deploy","azure_devops","cursor","northflank","spacelift","rundeck","cloud66","humanitec","ovh_kms","scaleway_secret_manager","vultr","hetzner","linode","digitalocean_ssh","ssh","keeper","oci_vault","huggingface"];

#[cfg(not(target_arch = "wasm32"))]
fn http_client() -> crate::http::Client { reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| reqwest::Client::builder().build().expect("http client")) }
#[cfg(target_arch = "wasm32")]
fn http_client() -> crate::http::Client { crate::http::Client::new() }
fn cfg<'a>(c: &'a Value, k: &str) -> &'a str { c.get(k).and_then(|v| v.as_str()).unwrap_or("") }
fn base(c: &Value, default: &str) -> String { let b = cfg(c, "base_url"); if b.is_empty() { default.to_string() } else { b.trim_end_matches('/').to_string() } }
async fn req(r: crate::http::RequestBuilder) -> Result<String, String> {
    let resp = r.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if status.is_success() { Ok(text) } else { Err(format!("HTTP {}: {}", status, text.chars().take(400).collect::<String>())) }
}
fn map_json(secrets: &[(String, String)]) -> Value { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); } Value::Object(m) }


/// Exchange a GCP service-account key for an OAuth access token. Static
/// `token` config still wins, so existing setups keep working.
async fn gcp_access_token(config: &Value) -> Result<String, String> {
    let token = cfg(config, "token"); if !token.is_empty() { return Ok(token.to_string()); }
    let raw = cfg(config, "service_account_json");
    if raw.is_empty() { return Err("gcp_secret_manager requires token or service_account_json".into()); }
    let service: Value = serde_json::from_str(raw).map_err(|e| format!("GCP service_account_json is invalid: {}", e))?;
    let email = service.get("client_email").and_then(Value::as_str).ok_or("GCP service account is missing client_email")?;
    let key = service.get("private_key").and_then(Value::as_str).ok_or("GCP service account is missing private_key")?;
    let token_uri = service.get("token_uri").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("https://oauth2.googleapis.com/token");
    let now = unix_now();
    let claims = json!({"iss": email, "scope": "https://www.googleapis.com/auth/cloud-platform", "aud": token_uri, "iat": now, "exp": now + 3600});
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let assertion = jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_rsa_pem(key.as_bytes()).map_err(|e| format!("GCP private key is invalid: {}", e))?).map_err(|e| format!("GCP JWT signing failed: {}", e))?;
    let body = format!("grant_type={}&assertion={}", form_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"), form_encode(&assertion));
    let text = req(http_client().post(token_uri).header("Content-Type", "application/x-www-form-urlencoded").body(body)).await.map_err(|e| format!("GCP token exchange failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("GCP token response is invalid: {}", e))?;
    value.get("access_token").and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("GCP token response is missing access_token: {}", text.chars().take(300).collect::<String>()))
}
/// Exchange an Azure app registration's client credentials for an access token.
async fn azure_access_token(config: &Value) -> Result<String, String> {
    let token = cfg(config, "token"); if !token.is_empty() { return Ok(token.to_string()); }
    let (tenant, client_id, secret) = (cfg(config, "tenant_id"), cfg(config, "client_id"), cfg(config, "client_secret"));
    if tenant.is_empty() || client_id.is_empty() || secret.is_empty() { return Err("azure_key_vault requires token, or tenant_id, client_id and client_secret".into()); }
    let endpoint = { let e = cfg(config, "token_endpoint"); if e.is_empty() { format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", enc(tenant)) } else { e.to_string() } };
    let body = format!("client_id={}&client_secret={}&scope={}&grant_type=client_credentials", form_encode(client_id), form_encode(secret), form_encode("https://vault.azure.net/.default"));
    let text = req(http_client().post(endpoint).header("Content-Type", "application/x-www-form-urlencoded").body(body)).await.map_err(|e| format!("Azure token exchange failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Azure token response is invalid: {}", e))?;
    value.get("access_token").and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("Azure token response is missing access_token: {}", text.chars().take(300).collect::<String>()))
}

pub async fn sync(kind: &str, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    validate_naming(config)?;
    let named: Vec<(String, String)> = secrets.iter().map(|(k, v)| (desired_name(config, k), v.clone())).collect();
    let secrets = named.as_slice();
    let client = http_client();
    match kind {
        "supabase" => { let items: Vec<Value> = secrets.iter().map(|(k,v)| json!({"name":k,"value":v})).collect();
            req(client.post(format!("{}/v1/projects/{}/secrets", base(config,"https://api.supabase.com"), cfg(config,"project_ref"))).bearer_auth(cfg(config,"token")).json(&items)).await?; Ok(format!("pushed {} secrets to Supabase", secrets.len())) }
        "nomad" => { req(client.put(format!("{}/v1/var/openwarp/default", base(config,"http://127.0.0.1:4646"))).header("X-Nomad-Token", cfg(config,"token")).json(&json!({"Items": map_json(secrets)}))).await?; Ok("pushed to Nomad variables".into()) }
        "coolify" => { for (k, v) in secrets { req(client.post(format!("{}/api/v1/applications/{}/envs", base(config,"https://app.coolify.io"), cfg(config,"app_uuid"))).bearer_auth(cfg(config,"token")).json(&json!({"key":k,"value":v,"is_preview":false}))).await?; } Ok(format!("pushed {} secrets to Coolify", secrets.len())) }
        "cloudflare_pages" => { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!({"value":v,"type":"secret_text"})); }
            req(client.put(format!("{}/client/v4/accounts/{}/pages/projects/{}/deployment_configs/production", base(config,"https://api.cloudflare.com"), cfg(config,"account_id"), cfg(config,"project"))).bearer_auth(cfg(config,"token")).json(&json!({"env_vars": Value::Object(m)}))).await?; Ok("pushed to Cloudflare Pages".into()) }
        "webhook" => webhook_sync(config, secrets).await,
        "gitlab" => { let base = if cfg(config,"base_url").is_empty() { "https://gitlab.com/api/v4" } else { cfg(config,"base_url") };
            for (k, v) in secrets { let url = format!("{}/projects/{}/variables", base, cfg(config,"project_id"));
                let r = client.post(&url).header("PRIVATE-TOKEN", cfg(config,"token")).json(&json!({"key":k,"value":v,"masked":true})).send().await.map_err(|e| e.to_string())?;
                if r.status().as_u16() == 400 { req(client.put(format!("{}/{}", url, k)).header("PRIVATE-TOKEN", cfg(config,"token")).json(&json!({"value":v}))).await?; }
            } Ok(format!("pushed {} secrets to GitLab", secrets.len())) }
        "github" => { // GitHub requires libsodium sealed-box; done by CLI-side helper if configured via `gh` compatible endpoint is not plain REST.
            // We fetch the repo key and encrypt with openwarp sealed box helper (see server note in README).
            github_sync(&client, config, secrets).await }
        "vercel" => { let team = cfg(config,"team_id"); let q = if team.is_empty() { String::new() } else { format!("?teamId={}", team) };
            for (k, v) in secrets { req(client.post(format!("{}/v10/projects/{}/env{}", base(config,"https://api.vercel.com"), cfg(config,"project_id"), q)).bearer_auth(cfg(config,"token")).json(&json!({"key":k,"value":v,"type":"encrypted","target":["production","preview","development"]}))).await?; }
            Ok(format!("pushed {} secrets to Vercel", secrets.len())) }
        "netlify" => { for (k, v) in secrets { req(client.put(format!("{}/api/v1/sites/{}/env/{}?context=all", base(config,"https://api.netlify.com"), cfg(config,"site_id"), k)).bearer_auth(cfg(config,"token")).json(&json!({"values":[{"value":v,"context":"all"}]}))).await?; } Ok(format!("pushed {} secrets to Netlify", secrets.len())) }
        "cloudflare" => { for (k, v) in secrets { req(client.put(format!("{}/client/v4/accounts/{}/workers/scripts/{}/secrets", base(config,"https://api.cloudflare.com"), cfg(config,"account_id"), cfg(config,"script_name"))).bearer_auth(cfg(config,"token")).json(&json!({"name":k,"text":v,"type":"secret_text"}))).await?; } Ok(format!("pushed {} secrets to Cloudflare Workers", secrets.len())) }
        "heroku" => { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); }
            req(client.patch(format!("{}/apps/{}/config-vars", base(config,"https://api.heroku.com"), cfg(config,"app"))).bearer_auth(cfg(config,"token")).header("Accept","application/vnd.heroku+json; version=3").json(&Value::Object(m))).await?; Ok("pushed to Heroku".into()) }
        "render" => { for (k, v) in secrets { req(client.put(format!("{}/v1/services/{}/env-vars/{}", base(config,"https://api.render.com"), cfg(config,"service_id"), k)).bearer_auth(cfg(config,"token")).json(&json!({"value":v}))).await?; } Ok(format!("pushed {} secrets to Render", secrets.len())) }
        "flyio" => { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); }
            req(client.post(format!("{}/v1/apps/{}/secrets", base(config,"https://api.machines.dev"), cfg(config,"app"))).bearer_auth(cfg(config,"token")).json(&json!({"values": Value::Object(m)}))).await.map_err(|_| "Fly.io secrets API rejected request; check app/token".to_string())?; Ok("pushed to Fly.io".into()) }
        "railway" => { let query = format!("mutation {{ variableCollectionUpsert(input: {{ projectId: \"{}\", environmentId: \"{}\", serviceId: \"{}\", variables: {} }}) }}", cfg(config,"project_id"), cfg(config,"environment_id"), cfg(config,"service_id"), map_json(secrets));
            req(client.post(format!("{}/graphql/v2", base(config,"https://backboard.railway.app"))).bearer_auth(cfg(config,"token")).json(&json!({"query": query}))).await?; Ok("pushed to Railway".into()) }
        "gcp_secret_manager" => { let project = cfg(config,"project"); let token = gcp_access_token(config).await?; for (k, v) in secrets { let name = k.to_lowercase().replace('_',"-");
                let _ = client.post(format!("{}/v1/projects/{}/secrets?secretId={}", base(config,"https://secretmanager.googleapis.com"), project, name)).bearer_auth(&token).json(&json!({"replication":{"automatic":{}}})).send().await;
                req(client.post(format!("{}/v1/projects/{}/secrets/{}:addVersion", base(config,"https://secretmanager.googleapis.com"), project, name)).bearer_auth(&token).json(&json!({"payload":{"data": openwarp_crypto::b64(v.as_bytes())}}))).await?; }
            Ok(format!("pushed {} secrets to GCP Secret Manager", secrets.len())) }
        "azure_key_vault" => { let token = azure_access_token(config).await?; for (k, v) in secrets { let name = k.to_lowercase().replace('_',"-");
                req(client.put(format!("{}/secrets/{}?api-version=7.4", if cfg(config,"base_url").is_empty() { format!("https://{}.vault.azure.net", cfg(config,"vault")) } else { base(config,"") }, name)).bearer_auth(&token).json(&json!({"value":v}))).await?; }
            Ok(format!("pushed {} secrets to Azure Key Vault", secrets.len())) }
        "kubernetes" => { let server = cfg(config,"api_server").trim_end_matches('/'); let ns = cfg(config,"namespace");
            let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(openwarp_crypto::b64(v.as_bytes()))); }
            let body = json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":cfg(config,"secret_name"),"namespace":ns},"type":"Opaque","data":Value::Object(m)});
            let url = format!("{}/api/v1/namespaces/{}/secrets/{}", server, ns, cfg(config,"secret_name"));
            let r = client.put(&url).bearer_auth(cfg(config,"token")).json(&body).send().await.map_err(|e| e.to_string())?;
            if r.status().as_u16() == 404 { req(client.post(format!("{}/api/v1/namespaces/{}/secrets", server, ns)).bearer_auth(cfg(config,"token")).json(&body)).await?; }
            Ok("pushed to Kubernetes".into()) }
        "hashicorp_vault" => { req(client.post(format!("{}/v1/{}", cfg(config,"addr").trim_end_matches('/'), cfg(config,"path"))).header("X-Vault-Token", cfg(config,"token")).json(&json!({"data": map_json(secrets)}))).await?; Ok("pushed to HashiCorp Vault".into()) }
        "digitalocean" => { let app_id = cfg(config,"app_id");
            let mut spec: Value = client.get(format!("{}/v2/apps/{}", base(config,"https://api.digitalocean.com"), app_id)).bearer_auth(cfg(config,"token")).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
            if let Some(svcs) = spec.get_mut("spec").and_then(|s| s.get_mut("services")).and_then(|v| v.as_array_mut()) { for svc in svcs.iter_mut() {
                if svc.get("envs").and_then(|e| e.as_array()).is_some() {
                    if let Some(existing) = svc.get_mut("envs").and_then(|e| e.as_array_mut()) {
                        for (k, v) in secrets {
                            if let Some(item) = existing.iter_mut().find(|x| x.get("key").and_then(|x| x.as_str()) == Some(k.as_str())) {
                                item["value"] = json!(v); item["type"] = json!("SECRET"); item["scope"] = json!("RUN_AND_BUILD_TIME");
                            } else { existing.push(json!({"key":k,"value":v,"scope":"RUN_AND_BUILD_TIME","type":"SECRET"})); }
                        }
                    }
                } else { svc["envs"] = json!(secrets.iter().map(|(k,v)| json!({"key":k,"value":v,"scope":"RUN_AND_BUILD_TIME","type":"SECRET"})).collect::<Vec<_>>()); }
            } }
            req(client.put(format!("{}/v2/apps/{}", base(config,"https://api.digitalocean.com"), app_id)).bearer_auth(cfg(config,"token")).json(&json!({"spec": spec["spec"]}))).await?; Ok("pushed to DigitalOcean App Platform".into()) }
        "instabox" => instabox_sync(config, secrets, &[]).await.map(|(report, _)| report),
        "boat" => boat_sync(config, secrets, &[]).await.map(|(report, _)| report),
        "daytona" => daytona_sync(config, secrets, &[]).await.map(|(report, _)| report),
        _ => Err(format!("unknown integration kind: {}", kind)),
    }
}


// Provider rotation adapters reuse the key-lifecycle primitives below. The
// adapter creates the replacement credential, the caller stores it, and only
// then finalizes by revoking the previous credential, so a failed write never
// destroys the working key.
pub struct RotatedValue {
    pub value: String,
    pub config: Value,
    pub cleanup: Option<Value>,
    pub rollback: Option<Value>,
}

fn rotation_name(config: &Value, key: &str) -> String {
    let configured = cfg(config, "name").trim();
    let name = if configured.is_empty() { format!("openwarp-{}", key) } else { configured.to_string() };
    name.chars().take(50).collect()
}

pub async fn rotate_value(config: &Value, key: &str, path: &str) -> Result<Option<RotatedValue>, String> {
    let kind = cfg(config, "kind");
    if kind.is_empty() || kind == "webhook" {
        let url = cfg(config, "rotation_url");
        if url.is_empty() { return Ok(None); }
        let provider = { let p = cfg(config, "provider"); if p.is_empty() { "webhook" } else { p } };
        let mut request = http_client().post(url).json(&json!({"key": key, "path": path, "provider": provider}));
        let token = cfg(config, "rotation_token");
        if !token.is_empty() { request = request.bearer_auth(token); }
        let text = req(request).await.map_err(|e| format!("rotation endpoint failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("rotation endpoint returned invalid JSON: {}", e))?;
        for field in ["value", "secret", "key", "api_key"] {
            if let Some(found) = value.get(field).and_then(Value::as_str) {
                if !found.is_empty() {
                    return Ok(Some(RotatedValue { value: found.to_string(), config: config.clone(), cleanup: None, rollback: None }));
                }
            }
        }
        return Err("rotation endpoint returned no value, secret, key or api_key field".into());
    }
    if kind == "resend" {
        let issued = resend_create_key(config, &rotation_name(config, key)).await?;
        let value = issued["token"].as_str().unwrap_or("");
        let id = issued["id"].as_str().unwrap_or("");
        if value.is_empty() || !key_ref_ok(id) { return Err("Resend rotation returned no token or id".into()); }
        let old = cfg(config, "key_id");
        let mut next = config.clone();
        next["key_id"] = json!(id);
        let cleanup = if old.is_empty() { None } else { Some(json!({"kind": "resend", "base_url": cfg(config, "base_url"), "api_key": cfg(config, "api_key"), "id": old})) };
        let rollback = Some(json!({"kind": "resend", "base_url": cfg(config, "base_url"), "api_key": cfg(config, "api_key"), "id": id}));
        return Ok(Some(RotatedValue { value: value.to_string(), config: next, cleanup, rollback }));
    }
    if kind == "openrouter" {
        let ttl = config.get("ttl_secs").and_then(Value::as_i64).unwrap_or(30 * 86400);
        let issued = openrouter_create_key(config, &rotation_name(config, key), ttl).await?;
        let value = issued["key"].as_str().unwrap_or("");
        let hash = issued["hash"].as_str().unwrap_or("");
        if value.is_empty() || !key_ref_ok(hash) { return Err("OpenRouter rotation returned no key or hash".into()); }
        let old = cfg(config, "hash");
        let mut next = config.clone();
        next["hash"] = json!(hash);
        let cleanup = if old.is_empty() { None } else { Some(json!({"kind": "openrouter", "base_url": cfg(config, "base_url"), "management_key": cfg(config, "management_key"), "hash": old})) };
        let rollback = Some(json!({"kind": "openrouter", "base_url": cfg(config, "base_url"), "management_key": cfg(config, "management_key"), "hash": hash}));
        return Ok(Some(RotatedValue { value: value.to_string(), config: next, cleanup, rollback }));
    }
    if kind == "openai" {
        let ttl = config.get("ttl_secs").and_then(Value::as_i64).unwrap_or(90 * 86400);
        let issued = openai_create_key(config, &rotation_name(config, key), ttl).await?;
        let value = issued["value"].as_str().unwrap_or("");
        let id = issued["id"].as_str().unwrap_or("");
        if value.is_empty() || !key_ref_ok(id) { return Err("OpenAI rotation returned no value or id".into()); }
        let old = cfg(config, "id");
        let mut next = config.clone();
        next["id"] = json!(id);
        let cleanup = if old.is_empty() { None } else { Some(json!({"kind": "openai", "base_url": cfg(config, "base_url"), "admin_key": cfg(config, "admin_key"), "project_id": cfg(config, "project_id"), "id": old})) };
        let rollback = Some(json!({"kind": "openai", "base_url": cfg(config, "base_url"), "admin_key": cfg(config, "admin_key"), "project_id": cfg(config, "project_id"), "id": id}));
        return Ok(Some(RotatedValue { value: value.to_string(), config: next, cleanup, rollback }));
    }
    Err(format!("unknown rotation adapter kind: {}", kind))
}

pub async fn finalize_rotation(cleanup: &Value) -> Result<(), String> {
    match cfg(cleanup, "kind") {
        "resend" => resend_revoke_key(cfg(cleanup, "base_url"), cfg(cleanup, "api_key"), cfg(cleanup, "id")).await,
        "openrouter" => openrouter_revoke_key(cfg(cleanup, "base_url"), cfg(cleanup, "management_key"), cfg(cleanup, "hash")).await,
        "openai" => openai_revoke_key(cfg(cleanup, "base_url"), cfg(cleanup, "admin_key"), cfg(cleanup, "project_id"), cfg(cleanup, "id")).await,
        other => Err(format!("unknown rotation cleanup kind: {}", other)),
    }
}

// Validate before storing an encrypted schedule config. Credentials are never
// echoed in the error, and provider base URLs go through the same public-host
// gate as the dynamic lease code.
pub fn validate_rotation_config(config: &Value) -> Result<(), String> {
    if config.as_object().map(|o| o.is_empty()).unwrap_or(true) { return Ok(()); }
    let kind = cfg(config, "kind");
    match kind {
        "postgres-static" => { if cfg!(target_arch="wasm32") { return Err("static PostgreSQL rotation requires the native server".into()); } crate::pglease::validate_static(cfg(config,"connection"),cfg(config,"username"))?; }
        "" | "webhook" => {
            let url = cfg(config, "rotation_url");
            if url.is_empty() { return Err("rotation config requires kind or rotation_url".into()); }
            lease_base(&json!({"base_url": url}), "")?;
        }
        "resend" => {
            if cfg(config, "api_key").is_empty() { return Err("resend rotation requires api_key".into()); }
            let permission = { let p = cfg(config, "permission"); if p.is_empty() { "sending_access" } else { p } };
            if !matches!(permission, "sending_access" | "full_access") { return Err("resend permission must be sending_access or full_access".into()); }
            if !cfg(config, "domain_id").is_empty() && permission != "sending_access" { return Err("resend domain_id is only valid with sending_access".into()); }
            lease_base(config, "https://api.resend.com")?;
        }
        "openrouter" => {
            if cfg(config, "management_key").is_empty() { return Err("openrouter rotation requires management_key".into()); }
            lease_base(config, "https://openrouter.ai/api/v1")?;
        }
        "openai" => {
            if cfg(config, "admin_key").is_empty() || !key_ref_ok(cfg(config, "project_id")) || !key_ref_ok(cfg(config, "service_account_id")) {
                return Err("openai rotation requires admin_key, project_id and service_account_id".into());
            }
            lease_base(config, "https://api.openai.com/v1")?;
        }
        other => return Err(format!("unknown rotation adapter kind: {}", other)),
    }
    Ok(())
}

pub fn rotation_kind(config: &Value) -> String {
    let kind = cfg(config, "kind");
    if kind.is_empty() && !cfg(config, "rotation_url").is_empty() { "webhook".into() } else { kind.to_string() }
}

// ---------- Trigger.dev ----------
pub struct TriggerTarget { pub project_ref: String, pub env: String, pub token: String }
pub fn trigger_targets(config: &Value) -> Vec<TriggerTarget> {
    let global_token = cfg(config, "token").to_string();
    if let Some(arr) = config.get("targets").and_then(|v| v.as_array()) {
        return arr.iter().map(|x| TriggerTarget{ project_ref: x.get("project_ref").and_then(|v| v.as_str()).unwrap_or("").to_string(), env: x.get("env").and_then(|v| v.as_str()).unwrap_or("prod").to_string(), token: x.get("token").and_then(|v| v.as_str()).unwrap_or(&global_token).to_string() }).collect();
    }
    let env = { let e = cfg(config, "target_env"); if e.is_empty() { cfg(config, "env") } else { e } };
    vec![TriggerTarget{ project_ref: cfg(config, "project_ref").to_string(), env: if env.is_empty() { "prod".to_string() } else { env.to_string() }, token: global_token }]
}
// Prefix and suffix wrap the key; name_template replaces both with a
// {{secretKey}}/{{environment}} pattern (Infisical calls this a key schema).
// `case` rewrites the source key first, so affixes keep their spelling.
fn env_subst(value: &str, environment: &str) -> String { value.replace("{{environment}}", environment) }
fn cased_key(config: &Value, key: &str) -> String {
    match cfg(config, "case") { "upper" => key.to_uppercase(), "lower" => key.to_lowercase(), _ => key.to_string() }
}
pub(crate) fn desired_name(config: &Value, key: &str) -> String {
    let environment = cfg(config, "_environment");
    let key = cased_key(config, key);
    let template = cfg(config, "name_template");
    if !template.is_empty() {
        template.replace("{{secretKey}}", &key).replace("{{environment}}", environment)
    } else {
        format!("{}{}{}", env_subst(cfg(config, "prefix"), environment), key, env_subst(cfg(config, "suffix"), environment))
    }
}
/// Literal text the schema puts before and after the source key, so a remote
/// name can be mapped back to the secret it came from.
fn naming_affixes(config: &Value) -> (String, String) {
    let environment = cfg(config, "_environment");
    let template = cfg(config, "name_template");
    if !template.is_empty() {
        let resolved = env_subst(template, environment);
        return match resolved.split_once("{{secretKey}}") { Some((before, after)) => (before.to_string(), after.to_string()), None => (String::new(), String::new()) };
    }
    (env_subst(cfg(config, "prefix"), environment), env_subst(cfg(config, "suffix"), environment))
}
pub fn local_name(config: &Value, remote: &str) -> String {
    let path = cfg(config, "path_prefix").trim_end_matches('/');
    let without_path = if path.is_empty() { remote } else { remote.strip_prefix(path).map(|s| s.trim_start_matches('/')).unwrap_or(remote) };
    let (prefix, suffix) = naming_affixes(config);
    let without_prefix = without_path.strip_prefix(&prefix).unwrap_or(without_path);
    without_prefix.strip_suffix(&suffix).unwrap_or(without_prefix).to_string()
}
/// A template without exactly one `{{secretKey}}` would collapse every key into
/// one remote name, so reject it before any adapter runs.
pub fn validate_naming(config: &Value) -> Result<(), String> {
    let case = cfg(config, "case");
    if !case.is_empty() && case != "upper" && case != "lower" { return Err(format!("case must be upper or lower (got {:?})", case)); }
    let template = cfg(config, "name_template");
    if template.is_empty() { return Ok(()); }
    let count = template.matches("{{secretKey}}").count();
    if count != 1 { return Err(format!("name_template must contain {{{{secretKey}}}} exactly once (found {})", count)); }
    Ok(())
}
fn trigger_desired(config: &Value, secrets: &[(String, String)]) -> Vec<(String, String)> {
    let include: Vec<String> = config.get("include_keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let exclude: Vec<String> = config.get("exclude_keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    secrets.iter().filter(|(k, _)| (include.is_empty() || include.contains(k)) && !exclude.contains(k)).map(|(k, v)| (desired_name(config, k), v.clone())).filter(|(n, _)| seen.insert(n.clone())).collect()
}
pub fn desired_names(config: &Value, secrets: &[(String, String)]) -> Vec<String> { trigger_desired(config, secrets).into_iter().map(|(n, _)| n).collect() }
/// The sync caller hands over `(path, key, value, type)`. Every other adapter
/// ignores the path and the type; the SSH file adapter groups by path.
pub fn secret_keys(secrets: &[(String, String, String, String)]) -> Vec<(String, String)> { secrets.iter().map(|(_, k, v, _)| (k.clone(), v.clone())).collect() }
pub async fn trigger_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let client = http_client(); let base_url = base(config, "https://api.trigger.dev");
    let mode = { let m = cfg(config, "mode"); if m.is_empty() { "upsert" } else { m } };
    let dry = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
    let desired = trigger_desired(config, secrets);
    let targets = trigger_targets(config);
    if targets.iter().any(|x| x.project_ref.is_empty() || x.token.is_empty()) { return Err("trigger requires token and project_ref (per target or global)".into()); }
    if let Some(bad) = targets.iter().find(|t| !matches!(t.env.as_str(), "dev" | "staging" | "prod")) { return Err(format!("trigger env must be dev, staging or prod (got {:?})", bad.env)); }
    let mut managed: Vec<String> = Vec::new(); let mut reports: Vec<String> = Vec::new(); let mut failures = 0;
    for tg in &targets {
        let root = format!("{}/api/v1/projects/{}/envvars/{}", base_url, tg.project_ref, tg.env);
        let list_text = match req(client.get(&root).bearer_auth(&tg.token)).await { Ok(x) => x, Err(e) => { failures += 1; reports.push(format!("{}/{}: list failed: {}", tg.project_ref, tg.env, e)); continue; } };
        let remote_list: Vec<Value> = serde_json::from_str(&list_text).unwrap_or_default();
        let remote: std::collections::HashMap<String, Option<String>> = remote_list.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("value").and_then(|x| x.as_str()).map(|s| s.to_string())))).collect();
        let (mut created, mut updated, mut unchanged, mut deleted) = (0, 0, 0, 0);
        if !dry {
            let mut bulk: Vec<Value> = Vec::new();
            for (name, value) in &desired { match remote.get(name) { None => bulk.push(json!({"name":name,"value":value})), Some(None) => bulk.push(json!({"name":name,"value":value})), Some(Some(old)) if old != value => bulk.push(json!({"name":name,"value":value})), Some(Some(_)) => unchanged += 1 } }
            created = bulk.iter().filter(|v| !remote.contains_key(v.get("name").and_then(|x| x.as_str()).unwrap_or(""))).count();
            updated = bulk.len() - created;
            if !bulk.is_empty() { if let Err(e) = req(client.post(format!("{}/import", root)).bearer_auth(&tg.token).json(&json!({"variables": bulk, "override": true}))).await { failures += 1; reports.push(format!("{}/{}: import failed: {}", tg.project_ref, tg.env, e)); continue; } }
            if mode == "mirror" { let mut delete_errors: Vec<String> = Vec::new();
                for name in previous_managed { if !desired.iter().any(|(n, _)| n == name) && remote.contains_key(name) {
                    match req(client.delete(format!("{}/{}", root, name)).bearer_auth(&tg.token)).await { Ok(_) => deleted += 1, Err(e) => delete_errors.push(format!("{}: {}", name, e)) } } }
                if !delete_errors.is_empty() { failures += 1; reports.push(format!("{}/{}: delete failed: {}", tg.project_ref, tg.env, delete_errors.join("; "))); } }
        } else { for (name, value) in &desired { match remote.get(name) { None => created += 1, Some(None) => updated += 1, Some(Some(old)) if old != value => updated += 1, Some(Some(_)) => unchanged += 1 } }
            if mode == "mirror" { for name in previous_managed { if !desired.iter().any(|(n, _)| n == name) && remote.contains_key(name) { deleted += 1; } } } }
        for (n, _) in &desired { if !managed.contains(n) { managed.push(n.clone()); } }
        reports.push(format!("{}/{}: created={} updated={} unchanged={} deleted={}{}", tg.project_ref, tg.env, created, updated, unchanged, deleted, if dry { " (dry-run)" } else { "" }));
    }
    if failures > 0 { return Err(reports.join("; ")); }
    let mut note = String::new();
    if config.get("mark_secret").and_then(|v| v.as_bool()).unwrap_or(false) { note = " NOTE: Trigger REST create/import schema documents name/value only, so secret marking could not be applied via API; mark these in the Trigger dashboard if needed.".to_string(); }
    Ok((format!("Trigger.dev sync{}: {}{}", if dry { " (dry-run)" } else { "" }, reports.join("; "), note), managed))
}
pub async fn trigger_test(config: &Value) -> Result<String, String> {
    let client = http_client(); let base_url = base(config, "https://api.trigger.dev"); let targets = trigger_targets(config);
    let tg = targets.first().ok_or("no target")?; if tg.project_ref.is_empty() || tg.token.is_empty() { return Err("trigger requires token and project_ref".into()); }
    let text = req(client.get(format!("{}/api/v1/projects/{}/envvars/{}", base_url, tg.project_ref, tg.env)).bearer_auth(&tg.token)).await?;
    let count = serde_json::from_str::<Vec<Value>>(&text).map(|v| v.len()).unwrap_or(0);
    Ok(format!("Trigger connection OK: project {} env {} currently has {} variables", tg.project_ref, tg.env, count))
}

fn instabox_config(config: &Value) -> Result<(String, String, reqwest::Url), String> {
    let key = if cfg(config, "api_key").trim().is_empty() { cfg(config, "token") } else { cfg(config, "api_key") }.trim();
    let key = key.strip_prefix("Bearer ").or_else(|| key.strip_prefix("bearer ")).unwrap_or(key).trim();
    let org = cfg(config, "org").trim();
    if key.is_empty() || org.is_empty() { return Err("Instabox requires api_key (or token) and org".into()); }
    let mut url = reqwest::Url::parse(&base(config, "https://api.instabox.sh")).map_err(|e| format!("Instabox invalid base_url: {}", e))?;
    url.path_segments_mut().map_err(|_| "Instabox base_url cannot be a base URL".to_string())?
        .pop_if_empty().extend(["v1", "orgs", org, "secrets"]);
    Ok((key.to_string(), org.to_string(), url))
}

async fn instabox_list(client: &crate::http::Client, root: &reqwest::Url, key: &str) -> Result<Vec<String>, String> {
    let text = req(client.get(root.clone()).header("X-API-Key", key)).await.map_err(|e| format!("Instabox list failed: {}", e))?;
    let response: Value = serde_json::from_str(&text).map_err(|e| format!("Instabox invalid list response: {}", e))?;
    let items = response.get("items").and_then(Value::as_array).ok_or("Instabox invalid list response: missing items array")?;
    items.iter().map(|item| item.get("name").and_then(Value::as_str).map(str::to_string)
        .ok_or_else(|| "Instabox invalid list response: missing secret name".to_string())).collect()
}

pub async fn instabox_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (key, org, root) = instabox_config(config)?;
    let delivery = match cfg(config, "delivery") { "" => "proxy", value => value };
    if delivery != "proxy" && delivery != "env" { return Err("Instabox delivery must be proxy or env".into()); }
    let hosts: Vec<String> = match config.get("hosts") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(|v| v.as_str().map(str::to_string).ok_or("Instabox hosts must be an array of strings".to_string())).collect::<Result<_, _>>()?,
        Some(_) => return Err("Instabox hosts must be an array of strings".into()),
    };
    if delivery == "env" && !hosts.is_empty() { return Err("Instabox env delivery requires empty hosts".into()); }
    if delivery == "proxy" {
        if hosts.len() > 32 { return Err("Instabox hosts allows at most 32 entries".into()); }
        if let Some(bad) = hosts.iter().find(|h| h.as_str() != "*" && (h.contains("://") || h.contains('/') || h.contains(':') || h.contains('*'))) { return Err(format!("Instabox host {:?} must be a bare DNS hostname or *", bad)); }
        if hosts.is_empty() && !config.get("allow_all_hosts").and_then(Value::as_bool).unwrap_or(false) { return Err("Instabox proxy delivery needs hosts, or set allow_all_hosts: true; without a host list the value may be sent to any public HTTPS destination".into()); }
    }
    let mode = match cfg(config, "mode") { "" => "upsert", value => value };
    if mode != "upsert" && mode != "mirror" { return Err("Instabox mode must be upsert or mirror".into()); }
    let dry = config.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    let desired = trigger_desired(config, secrets);
    let invalid: Vec<&str> = desired.iter().filter_map(|(name, _)| {
        let bytes = name.as_bytes();
        if bytes.len() > 128 || bytes.first().is_none_or(|b| !b.is_ascii_alphabetic() && *b != b'_') ||
            bytes.iter().skip(1).any(|b| !b.is_ascii_alphanumeric() && *b != b'_') { Some(name.as_str()) } else { None }
    }).collect();
    if !invalid.is_empty() { return Err(format!("Instabox invalid secret names: {}", invalid.join(", "))); }
    let reserved = ["PATH", "HOME", "BASH_ENV", "ENV", "IFS"];
    let blocked: Vec<&str> = desired.iter().filter_map(|(n, _)| { if reserved.contains(&n.as_str()) || n.starts_with("INSTABOX_") || n.starts_with("SSH_") { Some(n.as_str()) } else { None } }).collect();
    if !blocked.is_empty() { return Err(format!("Instabox reserves these environment variable names: {}", blocked.join(", "))); }
    let invalid_values: Vec<&str> = desired.iter().filter_map(|(name, value)| {
        if value.len() > 65536 || value.contains('\0') || (delivery == "proxy" && (value.contains('\r') || value.contains('\n'))) { Some(name.as_str()) } else { None }
    }).collect();
    if !invalid_values.is_empty() { return Err(format!("Instabox invalid secret values: {}", invalid_values.join(", "))); }
    let values = map_json(&desired);
    let managed: Vec<String> = values.as_object().unwrap().keys().cloned().collect();
    let client = http_client();
    let remote = instabox_list(&client, &root, &key).await?;
    let created = managed.iter().filter(|name| !remote.contains(name)).count();
    let replaced = managed.len() - created;
    let mut deleted = 0;
    if !dry {
        if !desired.is_empty() {
            let mut import = root.clone();
            import.path_segments_mut().map_err(|_| "Instabox invalid secrets URL".to_string())?.push("import");
            req(client.post(import).header("X-API-Key", &key).json(&json!({"values": values, "delivery": delivery, "hosts": hosts}))).await
                .map_err(|e| format!("Instabox import failed: {}", e))?;
        }
        if mode == "mirror" {
            let mut failures = Vec::new();
            let mut attempted = std::collections::HashSet::new();
            for name in previous_managed {
                if !managed.contains(name) && remote.contains(name) && attempted.insert(name) {
                    let mut url = root.clone();
                    url.path_segments_mut().map_err(|_| "Instabox invalid secrets URL".to_string())?.push(name);
                    match req(client.delete(url).header("X-API-Key", &key)).await {
                        Ok(_) => deleted += 1,
                        Err(e) => failures.push(format!("{}: {}", name, e)),
                    }
                }
            }
            if !failures.is_empty() { return Err(format!("Instabox delete failed after importing {} and deleting {}: {}", managed.len(), deleted, failures.join("; "))); }
        }
    }
    let report = if dry {
        format!("Instabox sync (dry-run): org {} delivery={} mode={} count={} would-create={} would-replace={}", org, delivery, mode, managed.len(), created, replaced)
    } else {
        format!("Instabox sync: org {} delivery={} mode={} imported={} deleted={}", org, delivery, mode, managed.len(), deleted)
    };
    Ok((report, managed))
}

pub async fn instabox_test(config: &Value) -> Result<String, String> {
    let (key, org, root) = instabox_config(config)?;
    let remote = instabox_list(&http_client(), &root, &key).await?;
    Ok(format!("Instabox connection OK: org {} currently has {} Secrets", org, remote.len()))
}

// ---------- Boat (boat.dev) sandbox environments ----------
fn enc(s: &str) -> String { s.bytes().map(|b| match b { b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(), b => format!("%{:02X}", b) }).collect() }
fn boat_env_ref(config: &Value) -> String { let e = cfg(config, "environment"); if e.is_empty() { cfg(config, "environment_id").to_string() } else { e.to_string() } }
fn dotenv_map(text: &str) -> std::collections::HashMap<String, String> {
    text.lines().filter_map(|line| { let l = line.trim(); if l.is_empty() || l.starts_with('#') { return None; } let (k, v) = l.split_once('=')?; Some((k.trim().to_string(), v.trim().trim_matches('"').trim_matches('\'').to_string())) }).collect() }
fn env_names_ok(names: &[&str]) -> Option<String> {
    let bad: Vec<&str> = names.iter().copied().filter(|n| { let b = n.as_bytes(); b.is_empty() || (!b[0].is_ascii_alphabetic() && b[0] != b'_') || b.iter().any(|c| !c.is_ascii_alphanumeric() && *c != b'_') }).collect();
    if bad.is_empty() { None } else { Some(bad.join(", ")) } }
async fn boat_find_env(client: &crate::http::Client, api: &str, key: &str, want: &str, org: &str) -> Result<(String, String, Value), String> {
    let url = if org.is_empty() { format!("{}/environments", api) } else { format!("{}/environments?org={}", api, enc(org)) };
    let text = req(client.get(&url).bearer_auth(key)).await.map_err(|e| format!("Boat list environments failed: {}", e))?;
    let list: Value = serde_json::from_str(&text).map_err(|e| format!("Boat invalid environment list: {}", e))?;
    let envs = list.get("environments").and_then(Value::as_array).ok_or("Boat invalid environment list: missing environments")?;
    let env = envs.iter().find(|e| e.get("id").and_then(Value::as_str) == Some(want) || e.get("name").and_then(Value::as_str) == Some(want))
        .ok_or_else(|| format!("Boat environment {:?} not found", want))?;
    let id = env.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    let name = env.get("name").and_then(Value::as_str).unwrap_or(want).to_string();
    Ok((id, name, env.clone())) }
pub async fn boat_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let key = cfg(config, "api_key"); if key.is_empty() { return Err("Boat requires api_key (a boat_ key)".into()); }
    let api = base(config, "https://boat.dev/api/v1");
    let mode = match cfg(config, "mode") { "" => "upsert", m => m };
    if mode != "upsert" && mode != "mirror" { return Err("boat mode must be upsert or mirror".into()); }
    let dry = config.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    let upgrade = config.get("upgrade").and_then(Value::as_bool).unwrap_or(false);
    let want = { let r = boat_env_ref(config); if r.is_empty() { "base".to_string() } else { r } };
    let client = http_client();
    let (eid, ename, env) = boat_find_env(&client, &api, key, &want, cfg(config, "org")).await?;
    let current = dotenv_map(env.get("envContents").and_then(Value::as_str).unwrap_or(""));
    let desired = trigger_desired(config, secrets);
    if let Some(bad) = env_names_ok(&desired.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()) { return Err(format!("Boat invalid environment variable names: {}", bad)); }
    let created = desired.iter().filter(|(n, _)| !current.contains_key(n)).count();
    let updated = desired.iter().filter(|(n, v)| current.get(n.as_str()).map(|c| c.as_str() != v.as_str()).unwrap_or(false)).count();
    let suffix = { let org = cfg(config, "org"); if org.is_empty() { String::new() } else { format!("?org={}", enc(org)) } };
    let mut deleted = 0;
    if !dry {
        for (name, value) in &desired { req(client.put(format!("{}/environments/{}/vars/{}{}", api, eid, name, suffix)).bearer_auth(key).json(&json!({"value": value}))).await.map_err(|e| format!("Boat set {} failed: {}", name, e))?; }
        if mode == "mirror" {
            let mut failures = Vec::new();
            for name in previous_managed { if !desired.iter().any(|(n, _)| n == name) && current.contains_key(name) {
                match req(client.delete(format!("{}/environments/{}/vars/{}{}", api, eid, name, suffix)).bearer_auth(key)).await { Ok(_) => deleted += 1, Err(e) => failures.push(format!("{}: {}", name, e)) } } }
            if !failures.is_empty() { return Err(format!("Boat delete failed after updating {}: {}", desired.len(), failures.join("; "))); }
        }
        if upgrade { req(client.post(format!("{}/environments/{}/upgrade{}", api, eid, suffix)).bearer_auth(key)).await.map_err(|e| format!("Boat upgrade failed after updating {} variables: {}", desired.len(), e))?; }
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Boat sync{}: environment {} created={} updated={} unchanged={} deleted={}{}", if dry { " (dry-run)" } else { "" }, ename, created, updated, desired.len() - created - updated, deleted, if upgrade && !dry { " (sandboxes upgraded)" } else { "" }), managed)) }
pub async fn boat_test(config: &Value) -> Result<String, String> {
    let key = cfg(config, "api_key"); if key.is_empty() { return Err("Boat requires api_key (a boat_ key)".into()); }
    let api = base(config, "https://boat.dev/api/v1");
    let want = { let r = boat_env_ref(config); if r.is_empty() { "base".to_string() } else { r } };
    let (_, ename, env) = boat_find_env(&http_client(), &api, key, &want, cfg(config, "org")).await?;
    let vars = dotenv_map(env.get("envContents").and_then(Value::as_str).unwrap_or("")).len();
    Ok(format!("Boat connection OK: environment {} currently has {} variables", ename, vars)) }

// ---------- Daytona vault secrets ----------
async fn daytona_send(key: &str, org: &str, r: crate::http::RequestBuilder) -> Result<String, String> {
    let r = if org.is_empty() { r.bearer_auth(key) } else { r.bearer_auth(key).header("X-Daytona-Organization-ID", org) };
    req(r).await }
async fn daytona_secret_list(client: &crate::http::Client, key: &str, org: &str, api: &str) -> Result<Vec<Value>, String> {
    let text = match daytona_send(key, org, client.get(format!("{}/secret/paginated?limit=200", api))).await {
        Ok(t) => t,
        Err(_) => daytona_send(key, org, client.get(format!("{}/secret", api))).await.map_err(|e| format!("Daytona list secrets failed: {}", e))?,
    };
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Daytona invalid secret list: {}", e))?;
    if let Some(items) = value.get("items").and_then(Value::as_array) { return Ok(items.clone()); }
    if let Some(items) = value.as_array() { return Ok(items.clone()); }
    Err("Daytona invalid secret list: missing items".into()) }
pub async fn daytona_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let key = cfg(config, "api_key"); if key.is_empty() { return Err("Daytona requires api_key".into()); }
    let api = base(config, "https://app.daytona.io/api");
    let org = cfg(config, "organization_id");
    if key.starts_with("eyJ") && org.is_empty() { return Err("Daytona JWT authentication requires organization_id".into()); }
    let mode = match cfg(config, "mode") { "" => "upsert", m => m };
    if mode != "upsert" && mode != "mirror" { return Err("daytona mode must be upsert or mirror".into()); }
    let dry = config.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    let hosts: Vec<String> = match config.get("hosts") { None => Vec::new(), Some(Value::Array(items)) => items.iter().map(|v| v.as_str().map(str::to_string).ok_or("Daytona hosts must be an array of strings".to_string())).collect::<Result<_, _>>()?, Some(_) => return Err("Daytona hosts must be an array of strings".into()) };
    let desired = trigger_desired(config, secrets);
    if let Some(bad) = env_names_ok(&desired.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()) { return Err(format!("Daytona invalid secret names: {}", bad)); }
    let client = http_client();
    let list = daytona_secret_list(&client, key, org, &api).await?;
    let by_name: std::collections::HashMap<String, String> = list.iter().filter_map(|s| Some((s.get("name")?.as_str()?.to_string(), s.get("id")?.as_str()?.to_string()))).collect();
    let created = desired.iter().filter(|(n, _)| !by_name.contains_key(n)).count();
    let updated = desired.len() - created;
    let mut deleted = 0;
    if !dry {
        for (name, value) in &desired {
            let mut body = json!({"value": value}); if !hosts.is_empty() { body["hosts"] = json!(hosts); }
            if let Some(id) = by_name.get(name) { daytona_send(key, org, client.patch(format!("{}/secret/{}", api, id)).json(&body)).await.map_err(|e| format!("Daytona update {} failed: {}", name, e))?; }
            else { let mut create = json!({"name": name, "value": value}); if !hosts.is_empty() { create["hosts"] = json!(hosts); }
                daytona_send(key, org, client.post(format!("{}/secret", api)).json(&create)).await.map_err(|e| format!("Daytona create {} failed: {}", name, e))?; }
        }
        if mode == "mirror" {
            let mut failures = Vec::new();
            for name in previous_managed { if !desired.iter().any(|(n, _)| n == name) { if let Some(id) = by_name.get(name) {
                match daytona_send(key, org, client.delete(format!("{}/secret/{}", api, id))).await { Ok(_) => deleted += 1, Err(e) => failures.push(format!("{}: {}", name, e)) } } } }
            if !failures.is_empty() { return Err(format!("Daytona delete failed after updating {}: {}", desired.len(), failures.join("; "))); }
        }
        let sandbox = cfg(config, "sandbox");
        if !sandbox.is_empty() { let mounts: Vec<Value> = desired.iter().map(|(n, _)| json!({n: n})).collect();
            daytona_send(key, org, client.put(format!("{}/sandbox/{}/secrets", api, sandbox)).json(&json!({"secrets": mounts}))).await.map_err(|e| format!("Daytona mount on sandbox {} failed: {}", sandbox, e))?; }
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    let mount = { let s = cfg(config, "sandbox"); if s.is_empty() { String::new() } else { format!(" mounted-on={}", s) } };
    Ok((format!("Daytona sync{}: created={} updated={} deleted={}{}", if dry { " (dry-run)" } else { "" }, created, updated, deleted, mount), managed)) }
pub async fn daytona_test(config: &Value) -> Result<String, String> {
    let key = cfg(config, "api_key"); if key.is_empty() { return Err("Daytona requires api_key".into()); }
    let api = base(config, "https://app.daytona.io/api");
    let org = cfg(config, "organization_id");
    if key.starts_with("eyJ") && org.is_empty() { return Err("Daytona JWT authentication requires organization_id".into()); }
    let list = daytona_secret_list(&http_client(), key, org, &api).await?;
    Ok(format!("Daytona connection OK: organisation currently has {} vault secrets", list.len())) }

async fn github_sync(client: &crate::http::Client, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    // Use GitHub public-key endpoint; sealed-box encryption is performed with crypto_box SalsaBox via helper binary if present.
    // Fallback: if config contains pre-encrypted payloads, push them; otherwise report precise blocker per secret.
    let owner = cfg(config, "owner"); let repo = cfg(config, "repo");
    let key_resp: Value = client.get(format!("{}/repos/{}/{}/actions/secrets/public-key", base(config,"https://api.github.com"), owner, repo)).bearer_auth(cfg(config,"token")).header("User-Agent","openwarp").send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let _key_id = key_resp.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
    // Sealed box is libsodium XSalsa20-Poly1305, not XChaCha; implemented in openwarp-crypto via `seal_for_github` when built with that helper.
    let mut pushed = 0;
    for (k, v) in secrets {
        match openwarp_crypto::seal_github(key_resp.get("key").and_then(|x| x.as_str()).unwrap_or(""), v.as_bytes()) {
            Ok(enc) => { req(client.put(format!("{}/repos/{}/{}/actions/secrets/{}", base(config,"https://api.github.com"), owner, repo, k)).bearer_auth(cfg(config,"token")).header("User-Agent","openwarp").json(&json!({"encrypted_value":enc,"key_id":_key_id}))).await?; pushed += 1; }
            Err(e) => return Err(format!("GitHub sealed-box failed for {}: {}", k, e)),
        }
    }
    Ok(format!("pushed {} secrets to GitHub Actions", pushed))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> { let mut m = HmacSha256::new_from_slice(key).unwrap(); m.update(data); m.finalize().into_bytes().to_vec() }
/// Same construction as the audit log streams: HMAC-SHA256 over `timestamp.body`,
/// sent as `t=<unix>,v1=<hex>`. An empty secret keeps the unsigned bearer-only post.
fn webhook_signature(secret: &str, timestamp: i64, body: &str) -> String {
    format!("t={},v1={}", timestamp, hex(&hmac(secret.as_bytes(), format!("{}.{}", timestamp, body).as_bytes())))
}
pub async fn webhook_sync(config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    let url = cfg(config, "url").trim();
    if url.is_empty() { return Err("webhook requires url".into()); }
    let body = json!({"secrets": map_json(secrets)}).to_string();
    let mut request = http_client().post(url).header("content-type", "application/json").body(body.clone());
    let token = cfg(config, "token");
    if !token.is_empty() { request = request.header("Authorization", format!("Bearer {}", token)); }
    // `signing_secret` is the dedicated key; `secret` is accepted so a config
    // copied from a log stream verifies with the same code.
    let signing = { let s = cfg(config, "signing_secret"); if s.is_empty() { cfg(config, "secret") } else { s } };
    if !signing.is_empty() {
        let signed_at = unix_now();
        request = request.header("X-OpenWarp-Timestamp", signed_at.to_string()).header("X-OpenWarp-Signature", webhook_signature(signing, signed_at, &body));
    }
    req(request).await?;
    Ok(format!("pushed {} secrets to webhook{}", secrets.len(), if signing.is_empty() { "" } else { " (signed)" }))
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }
// ---------- Shared sync options ----------
fn sync_mode<'a>(config: &'a Value, provider: &str) -> Result<&'a str, String> {
    match cfg(config, "mode") { "" | "upsert" => Ok("upsert"), "mirror" => Ok("mirror"), other => Err(format!("{} mode must be upsert or mirror (got {:?})", provider, other)) }
}
fn is_dry(config: &Value) -> bool { config.get("dry_run").and_then(Value::as_bool).unwrap_or(false) }

/// Merge desired values into an existing env map. In mirror mode only names this
/// integration previously managed are removed, so unrelated remote values survive.
fn merge_pairs(current: &HashMap<String, String>, desired: &[(String, String)], previous: &[String], mirror: bool) -> (BTreeMap<String, String>, usize, usize, usize, usize) {
    let mut out: BTreeMap<String, String> = current.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    for (k, v) in desired {
        match current.get(k) {
            None => { created += 1; out.insert(k.clone(), v.clone()); }
            Some(old) if old == v => unchanged += 1,
            Some(_) => { updated += 1; out.insert(k.clone(), v.clone()); }
        }
    }
    let mut deleted = 0;
    if mirror {
        for name in previous { if !desired.iter().any(|(k, _)| k == name) && out.remove(name).is_some() { deleted += 1; } }
    }
    (out, created, updated, unchanged, deleted)
}

fn dotenv_quote(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:/@+=,%~".contains(&b)) { value.to_string() }
    else { format!("'{}'", value.replace('\'', "'\\''")) }
}
fn dotenv_render(map: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (k, v) in map { out.push_str(k); out.push('='); out.push_str(&dotenv_quote(v)); out.push('\n'); }
    out
}
fn config_i64(config: &Value, key: &str) -> Option<i64> {
    config.get(key).and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
}

// ---------- AWS SigV4 ----------
struct AwsReq<'a> { service: &'a str, region: &'a str, ak: &'a str, sk: &'a str, session_token: &'a str, target: &'a str, payload: &'a str, endpoint: &'a str }
async fn aws_signed(client: &crate::http::Client, r: AwsReq<'_>) -> Result<String, String> {
    let host_default = format!("{}.{}.amazonaws.com", r.service, r.region); let url_default = format!("https://{}", host_default);
    let (host, url, uri) = if r.endpoint.is_empty() { (host_default, url_default, "/".to_string()) } else {
        let parsed = reqwest::Url::parse(r.endpoint).map_err(|e| format!("invalid AWS endpoint: {}", e))?;
        let host = match parsed.port() { Some(port) => format!("{}:{}", parsed.host_str().unwrap_or(""), port), None => parsed.host_str().unwrap_or("").to_string() };
        let uri = if parsed.path().is_empty() { "/".to_string() } else { parsed.path().to_string() };
        (host, r.endpoint.trim_end_matches('/').to_string(), uri)
    };
    let now = chrono_now(); let (date, amzdate) = (now[..8].to_string(), now.clone());
    let payload_hash = hex(&Sha256::digest(r.payload.as_bytes()));
    let mut headers = vec![("content-type", "application/x-amz-json-1.1".to_string()), ("host", host), ("x-amz-date", amzdate.clone())];
    if !r.session_token.is_empty() { headers.push(("x-amz-security-token", r.session_token.to_string())); }
    headers.push(("x-amz-target", r.target.to_string()));
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{}:{}\n", k, v)).collect();
    let signed_headers: String = headers.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let canonical = format!("POST\n{}\n\n{}\n{}\n{}", uri, canonical_headers, signed_headers, payload_hash);
    let scope = format!("{}/{}/{}/aws4_request", date, r.region, r.service);
    let to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amzdate, scope, hex(&Sha256::digest(canonical.as_bytes())));
    let k_date = hmac(format!("AWS4{}", r.sk).as_bytes(), date.as_bytes()); let k_region = hmac(&k_date, r.region.as_bytes()); let k_svc = hmac(&k_region, r.service.as_bytes()); let k_sign = hmac(&k_svc, b"aws4_request");
    let sig = hex(&hmac(&k_sign, to_sign.as_bytes()));
    let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}", r.ak, scope, signed_headers, sig);
    let mut request = client.post(&url).header("Content-Type", "application/x-amz-json-1.1").header("X-Amz-Date", &amzdate).header("X-Amz-Target", r.target).header("Authorization", auth);
    if !r.session_token.is_empty() { request = request.header("X-Amz-Security-Token", r.session_token); }
    req(request.body(r.payload.to_string())).await
}
#[allow(clippy::too_many_arguments)]
async fn aws_call(client: &crate::http::Client, config: &Value, service: &str, region: &str, ak: &str, sk: &str, target: &str, payload: &Value) -> Result<Value, String> {
    let body = payload.to_string();
    let text = aws_signed(client, AwsReq { service, region, ak, sk, session_token: cfg(config, "session_token"), target, payload: &body, endpoint: cfg(config, "endpoint") }).await?;
    if text.trim().is_empty() { Ok(json!({})) } else { serde_json::from_str(&text).map_err(|e| format!("AWS {} returned invalid JSON: {}", target, e)) }
}
fn aws_creds(config: &Value) -> Result<(&str, &str, &str), String> {
    let (region, ak, sk) = (cfg(config, "region"), cfg(config, "access_key_id"), cfg(config, "secret_access_key"));
    if region.is_empty() || ak.is_empty() || sk.is_empty() { return Err("AWS integration requires region, access_key_id, secret_access_key".into()); }
    Ok((region, ak, sk))
}
/// When `role_arn` is configured, exchange the base credentials for short-lived
/// role credentials before signing. The integration then behaves like a workload
/// identity instead of a static key pair.
async fn aws_effective_config(config: &Value) -> Result<Value, String> {
    if cfg(config, "role_arn").is_empty() { return Ok(config.clone()); }
    let creds = sts_assume_role(config).await?;
    let mut out = config.clone();
    out["access_key_id"] = creds.get("access_key_id").cloned().unwrap_or(json!(""));
    out["secret_access_key"] = creds.get("secret_access_key").cloned().unwrap_or(json!(""));
    out["session_token"] = creds.get("session_token").cloned().unwrap_or(json!(""));
    Ok(out)
}
fn aws_secret_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 512 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+=.@-".contains(&b))
}
fn ssm_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 1011 && !name.contains(' ') && !name.contains("//") && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
}

async fn aws_sm_list(client: &crate::http::Client, config: &Value, region: &str, ak: &str, sk: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new(); let mut token = String::new();
    loop {
        let mut payload = json!({"MaxResults": 100});
        if !token.is_empty() { payload["NextToken"] = json!(token); }
        let value = aws_call(client, config, "secretsmanager", region, ak, sk, "secretsmanager.ListSecrets", &payload).await?;
        if let Some(items) = value.get("SecretList").and_then(Value::as_array) {
            for item in items { if let Some(name) = item.get("Name").and_then(Value::as_str) { out.push(name.to_string()); } }
        }
        token = value.get("NextToken").and_then(Value::as_str).unwrap_or("").to_string();
        if token.is_empty() { break; }
    }
    Ok(out)
}

pub async fn aws_secrets_manager_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let effective = aws_effective_config(config).await?;
    let config = &effective;
    let (region, ak, sk) = aws_creds(config)?;
    let mode = sync_mode(config, "aws_secrets_manager")?;
    let dry = is_dry(config);
    let mapping = { let m = cfg(config, "mapping"); if !m.is_empty() { m } else if !cfg(config, "secret_id").is_empty() { "many_to_one" } else { "one_to_one" } };
    let client = http_client();
    if mapping == "many_to_one" {
        let secret_id = cfg(config, "secret_id");
        if secret_id.is_empty() { return Err("aws_secrets_manager many_to_one requires secret_id".into()); }
        if mode == "mirror" { return Err("aws_secrets_manager many_to_one cannot mirror keys; use mapping one_to_one".into()); }
        let desired = trigger_desired(config, secrets);
        let json_body = map_json(&desired).to_string();
        if !dry {
            let body = json!({"SecretId": secret_id, "SecretString": json_body});
            match aws_call(&client, config, "secretsmanager", region, ak, sk, "secretsmanager.UpdateSecret", &body).await {
                Ok(_) => {}
                Err(e) if e.to_lowercase().contains("resourcenotfound") => {
                    let mut create = json!({"Name": secret_id, "SecretString": json_body});
                    if !cfg(config, "kms_key_id").is_empty() { create["KmsKeyId"] = json!(cfg(config, "kms_key_id")); }
                    aws_call(&client, config, "secretsmanager", region, ak, sk, "secretsmanager.CreateSecret", &create).await.map_err(|e| format!("create {} failed: {}", secret_id, e))?;
                }
                Err(e) => return Err(format!("update {} failed: {}", secret_id, e)),
            }
        }
        return Ok((format!("AWS Secrets Manager sync{}: wrote {} keys into {}", if dry { " (dry-run)" } else { "" }, desired.len(), secret_id), Vec::new()));
    }
    if mapping != "one_to_one" { return Err("aws_secrets_manager mapping must be one_to_one or many_to_one".into()); }
    let desired = trigger_desired(config, secrets);
    if let Some(bad) = desired.iter().find(|(name, _)| !aws_secret_name_ok(name)).map(|(name, _)| name.as_str()) { return Err(format!("invalid AWS Secrets Manager name: {:?}", bad)); }
    let remote = aws_sm_list(&client, config, region, ak, sk).await?;
    let created = desired.iter().filter(|(name, _)| !remote.contains(name)).count();
    let updated = desired.len() - created;
    let deleted = previous_managed.iter().filter(|name| !desired.iter().any(|(n, _)| n == *name) && remote.contains(name)).count();
    if !dry {
        for (name, value) in &desired {
            let body = json!({"SecretId": name, "SecretString": value});
            match aws_call(&client, config, "secretsmanager", region, ak, sk, "secretsmanager.PutSecretValue", &body).await {
                Ok(_) => {}
                Err(e) if e.to_lowercase().contains("resourcenotfound") => {
                    let mut create = json!({"Name": name, "SecretString": value});
                    if !cfg(config, "kms_key_id").is_empty() { create["KmsKeyId"] = json!(cfg(config, "kms_key_id")); }
                    aws_call(&client, config, "secretsmanager", region, ak, sk, "secretsmanager.CreateSecret", &create).await.map_err(|e| format!("create {} failed: {}", name, e))?;
                }
                Err(e) => return Err(format!("update {} failed: {}", name, e)),
            }
        }
        if mode == "mirror" {
            for name in previous_managed {
                if desired.iter().any(|(n, _)| n == name) || !remote.contains(name) { continue; }
                let mut body = json!({"SecretId": name});
                if config.get("force_delete").and_then(Value::as_bool).unwrap_or(false) { body["ForceDeleteWithoutRecovery"] = json!(true); } else { body["RecoveryWindowInDays"] = json!(7); }
                aws_call(&client, config, "secretsmanager", region, ak, sk, "secretsmanager.DeleteSecret", &body).await.map_err(|e| format!("delete {} failed: {}", name, e))?;
            }
        }
    }
    let names = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("AWS Secrets Manager sync{}: created={} updated={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, deleted), names))
}

pub async fn aws_secrets_manager_test(config: &Value) -> Result<String, String> {
    let effective = aws_effective_config(config).await?;
    let config = &effective;
    let (region, ak, sk) = aws_creds(config)?;
    let value = aws_call(&http_client(), config, "secretsmanager", region, ak, sk, "secretsmanager.ListSecrets", &json!({"MaxResults": 1})).await?;
    let count = value.get("SecretList").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    Ok(format!("AWS Secrets Manager connection OK: region {} returned a secret list ({} item(s))", region, count))
}

fn ssm_path(config: &Value) -> String {
    let path = cfg(config, "path_prefix").trim_end_matches('/');
    if path.is_empty() { String::new() } else if path.starts_with('/') { path.to_string() } else { format!("/{}", path) }
}
async fn ssm_list(client: &crate::http::Client, config: &Value, region: &str, ak: &str, sk: &str) -> Result<Vec<String>, String> {
    let path = ssm_path(config);
    let mut out = Vec::new(); let mut token = String::new();
    loop {
        let mut payload = if path.is_empty() { json!({"MaxResults": 50}) } else { json!({"Path": path, "Recursive": true, "MaxResults": 10}) };
        if !token.is_empty() { payload["NextToken"] = json!(token); }
        let target = if path.is_empty() { "AmazonSSM.DescribeParameters" } else { "AmazonSSM.GetParametersByPath" };
        let value = aws_call(client, config, "ssm", region, ak, sk, target, &payload).await?;
        if let Some(items) = value.get("Parameters").and_then(Value::as_array) {
            for item in items { if let Some(name) = item.get("Name").and_then(Value::as_str) { out.push(name.to_string()); } }
        }
        token = value.get("NextToken").and_then(Value::as_str).unwrap_or("").to_string();
        if token.is_empty() { break; }
    }
    Ok(out)
}
fn ssm_full_name(config: &Value, name: &str) -> String {
    let path = ssm_path(config);
    if path.is_empty() { name.to_string() } else { format!("{}/{}", path, name) }
}

pub async fn aws_parameter_store_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let effective = aws_effective_config(config).await?;
    let config = &effective;
    let (region, ak, sk) = aws_creds(config)?;
    let mode = sync_mode(config, "aws_parameter_store")?;
    let dry = is_dry(config);
    let kind = match cfg(config, "type") { "" => "SecureString", "String" | "StringList" | "SecureString" => cfg(config, "type"), other => return Err(format!("aws_parameter_store type must be String, StringList or SecureString (got {:?})", other)) };
    let tier = cfg(config, "tier");
    if !tier.is_empty() && tier != "Standard" && tier != "Advanced" && tier != "Intelligent-Tiering" { return Err("aws_parameter_store tier must be Standard, Advanced or Intelligent-Tiering".into()); }
    if tier != "Advanced" && tier != "Intelligent-Tiering" {
        if let Some((name, _)) = secrets.iter().find(|(_, v)| v.len() > 4096) { return Err(format!("AWS Parameter Store Standard tier values are limited to 4096 bytes; set tier Advanced for {:?}", name)); }
    }
    let desired: Vec<(String, String)> = trigger_desired(config, secrets).into_iter().map(|(name, value)| (ssm_full_name(config, &name), value)).collect();
    if let Some(bad) = desired.iter().find(|(name, _)| !ssm_name_ok(name)).map(|(name, _)| name.as_str()) { return Err(format!("invalid AWS Parameter Store name: {:?}", bad)); }
    let client = http_client();
    let remote = ssm_list(&client, config, region, ak, sk).await?;
    let created = desired.iter().filter(|(name, _)| !remote.contains(name)).count();
    let updated = desired.len() - created;
    let deleted = previous_managed.iter().filter(|name| !desired.iter().any(|(n, _)| n == *name) && remote.contains(name)).count();
    if !dry {
        for (name, value) in &desired {
            let mut body = json!({"Name": name, "Value": value, "Type": kind, "Overwrite": true});
            if !cfg(config, "kms_key_id").is_empty() { body["KeyId"] = json!(cfg(config, "kms_key_id")); }
            if !tier.is_empty() { body["Tier"] = json!(tier); }
            aws_call(&client, config, "ssm", region, ak, sk, "AmazonSSM.PutParameter", &body).await.map_err(|e| format!("put {} failed: {}", name, e))?;
        }
        if mode == "mirror" {
            for name in previous_managed {
                if desired.iter().any(|(n, _)| n == name) || !remote.contains(name) { continue; }
                aws_call(&client, config, "ssm", region, ak, sk, "AmazonSSM.DeleteParameter", &json!({"Name": name})).await.map_err(|e| format!("delete {} failed: {}", name, e))?;
            }
        }
    }
    let names = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("AWS Parameter Store sync{}: created={} updated={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, deleted), names))
}

pub async fn aws_parameter_store_test(config: &Value) -> Result<String, String> {
    let effective = aws_effective_config(config).await?;
    let config = &effective;
    let (region, ak, sk) = aws_creds(config)?;
    let value = aws_call(&http_client(), config, "ssm", region, ak, sk, "AmazonSSM.DescribeParameters", &json!({"MaxResults": 1})).await?;
    let count = value.get("Parameters").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    Ok(format!("AWS Parameter Store connection OK: region {} returned a parameter list ({} item(s))", region, count))
}

// ---------- 1Password Connect ----------
fn onepassword_config(config: &Value) -> Result<(String, String, String, String, String), String> {
    let raw = { let v = cfg(config, "connect_url"); if v.is_empty() { cfg(config, "base_url") } else { v } };
    let base = raw.trim_end_matches('/').trim_end_matches("/v1").trim_end_matches('/').to_string();
    if base.is_empty() { return Err("1Password requires connect_url (the Connect server URL)".into()); }
    let token = { let t = cfg(config, "token"); if t.is_empty() { cfg(config, "access_token") } else { t } };
    let vault = { let v = cfg(config, "vault_id"); if v.is_empty() { cfg(config, "vault") } else { v } };
    if token.is_empty() || vault.is_empty() { return Err("1Password requires token and vault_id".into()); }
    let label = { let v = cfg(config, "value_label"); if v.is_empty() { "value" } else { v } };
    let category = { let v = cfg(config, "category"); if v.is_empty() { "API_CREDENTIAL" } else { v } };
    Ok((base, token.to_string(), vault.to_string(), label.to_string(), category.to_string()))
}
async fn onepassword_items(client: &crate::http::Client, base: &str, token: &str, vault: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/v1/vaults/{}/items", base, vault)).bearer_auth(token)).await.map_err(|e| format!("1Password list items failed: {}", e))?;
    if let Ok(items) = serde_json::from_str::<Vec<Value>>(&text) { return Ok(items); }
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("1Password invalid item list: {}", e))?;
    value.get("items").and_then(Value::as_array).cloned().ok_or("1Password invalid item list: missing items".into())
}
fn onepassword_field<'a>(item: &'a Value, label: &str) -> Option<&'a str> {
    item.get("fields").and_then(Value::as_array)?.iter().find(|f| f.get("label").and_then(Value::as_str) == Some(label) || f.get("id").and_then(Value::as_str) == Some(label)).and_then(|f| f.get("value")).and_then(Value::as_str)
}
fn onepassword_set_field(item: &mut Value, label: &str, value: &str) {
    let fields = item.get_mut("fields").and_then(Value::as_array_mut);
    match fields {
        Some(fields) => {
            if let Some(field) = fields.iter_mut().find(|f| f.get("label").and_then(Value::as_str) == Some(label) || f.get("id").and_then(Value::as_str) == Some(label)) { field["value"] = json!(value); }
            else { fields.push(json!({"label": label, "value": value, "type": "CONCEALED"})); }
        }
        None => { item["fields"] = json!([{"label": label, "value": value, "type": "CONCEALED"}]); }
    }
}
pub async fn onepassword_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token, vault, label, category) = onepassword_config(config)?;
    let mode = sync_mode(config, "1password")?;
    let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(name, _)| name.is_empty() || name.len() > 256) { return Err(format!("invalid 1Password item title: {:?}", name)); }
    let client = http_client();
    let items = onepassword_items(&client, &base, &token, &vault).await?;
    let by_title: HashMap<String, String> = items.iter().filter_map(|i| Some((i.get("title")?.as_str()?.to_string(), i.get("id")?.as_str()?.to_string()))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    let mut managed = Vec::new();
    for (name, value) in &desired {
        match by_title.get(name) {
            Some(id) => {
                let text = req(client.get(format!("{}/v1/vaults/{}/items/{}", base, vault, id)).bearer_auth(&token)).await.map_err(|e| format!("1Password read {} failed: {}", name, e))?;
                let item: Value = serde_json::from_str(&text).map_err(|e| format!("1Password invalid item {}: {}", name, e))?;
                if onepassword_field(&item, &label) == Some(value.as_str()) { unchanged += 1; }
                else {
                    if !dry {
                        let mut body = json!({"id": id, "title": name, "vault": {"id": vault}, "category": item.get("category").and_then(Value::as_str).unwrap_or(category.as_str())});
                        let fields = item.get("fields").cloned().unwrap_or(json!([]));
                        let mut wrapper = json!({"fields": fields});
                        onepassword_set_field(&mut wrapper, &label, value);
                        body["fields"] = wrapper["fields"].clone();
                        if let Some(sections) = item.get("sections") { body["sections"] = sections.clone(); }
                        if let Some(tags) = item.get("tags") { body["tags"] = tags.clone(); }
                        if let Some(urls) = item.get("urls") { body["urls"] = urls.clone(); }
                        req(client.put(format!("{}/v1/vaults/{}/items/{}", base, vault, id)).bearer_auth(&token).json(&body)).await.map_err(|e| format!("1Password update {} failed: {}", name, e))?;
                    }
                    updated += 1;
                }
            }
            None => {
                if !dry { req(client.post(format!("{}/v1/vaults/{}/items", base, vault)).bearer_auth(&token).json(&json!({"title": name, "vault": {"id": vault}, "category": category, "fields": [{"label": label, "value": value, "type": "CONCEALED"}]}))).await.map_err(|e| format!("1Password create {} failed: {}", name, e))?; }
                created += 1;
            }
        }
        managed.push(name.clone());
    }
    let mut deleted = 0;
    if mode == "mirror" {
        for name in previous_managed {
            if desired.iter().any(|(n, _)| n == name) { continue; }
            if let Some(id) = by_title.get(name) {
                if !dry { req(client.delete(format!("{}/v1/vaults/{}/items/{}", base, vault, id)).bearer_auth(&token)).await.map_err(|e| format!("1Password delete {} failed: {}", name, e))?; }
                deleted += 1;
            }
        }
    }
    Ok((format!("1Password sync{}: vault={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, vault, created, updated, unchanged, deleted), managed))
}
pub async fn onepassword_test(config: &Value) -> Result<String, String> {
    let (base, token, vault, _, _) = onepassword_config(config)?;
    let text = req(http_client().get(format!("{}/v1/vaults/{}", base, vault)).bearer_auth(&token)).await?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("1Password invalid vault response: {}", e))?;
    let name = value.get("name").and_then(Value::as_str).unwrap_or(&vault);
    Ok(format!("1Password Connect OK: vault {} is reachable", name))
}

// ---------- Dokploy ----------
fn dokploy_config(config: &Value) -> Result<(String, String, String, bool), String> {
    let base = cfg(config, "base_url").trim_end_matches('/').to_string();
    let key = cfg(config, "api_key").trim();
    let app = cfg(config, "application_id").trim();
    let compose = cfg(config, "compose_id").trim();
    if base.is_empty() || key.is_empty() { return Err("Dokploy requires base_url and api_key".into()); }
    if app.is_empty() == compose.is_empty() { return Err("Dokploy requires exactly one of application_id or compose_id".into()); }
    let id = if app.is_empty() { compose.to_string() } else { app.to_string() };
    Ok((base, key.to_string(), id, !app.is_empty()))
}
pub async fn dokploy_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, key, id, is_app) = dokploy_config(config)?;
    let mode = sync_mode(config, "dokploy")?;
    let dry = is_dry(config);
    let client = http_client();
    let read_url = if is_app { format!("{}/api/application.one?applicationId={}", base, form_encode(&id)) } else { format!("{}/api/compose.one?composeId={}", base, form_encode(&id)) };
    let text = req(client.get(&read_url).header("x-api-key", &key)).await.map_err(|e| format!("Dokploy read failed: {}", e))?;
    let current: Value = serde_json::from_str(&text).map_err(|e| format!("Dokploy invalid read response: {}", e))?;
    let current_map = dotenv_map(current.get("env").and_then(Value::as_str).unwrap_or(""));
    let desired = trigger_desired(config, secrets);
    if let Some(bad) = env_names_ok(&desired.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()) { return Err(format!("Dokploy invalid environment variable names: {}", bad)); }
    if let Some((name, _)) = desired.iter().find(|(_, v)| v.contains('\n') || v.contains('\r')) { return Err(format!("Dokploy env values cannot contain line breaks: {:?}", name)); }
    let (merged, created, updated, unchanged, deleted) = merge_pairs(&current_map, &desired, previous_managed, mode == "mirror");
    if !dry {
        if is_app {
            let body = json!({"applicationId": id, "env": dotenv_render(&merged), "buildArgs": current.get("buildArgs").cloned().unwrap_or(json!("")), "buildSecrets": current.get("buildSecrets").cloned().unwrap_or(json!("")), "createEnvFile": current.get("createEnvFile").and_then(Value::as_bool).unwrap_or(true)});
            req(client.post(format!("{}/api/application.saveEnvironment", base)).header("x-api-key", &key).json(&body)).await.map_err(|e| format!("Dokploy saveEnvironment failed: {}", e))?;
            if config.get("redeploy").and_then(Value::as_bool).unwrap_or(false) { req(client.post(format!("{}/api/application.redeploy", base)).header("x-api-key", &key).json(&json!({"applicationId": id}))).await.map_err(|e| format!("Dokploy redeploy failed: {}", e))?; }
        } else {
            req(client.post(format!("{}/api/compose.saveEnvironment", base)).header("x-api-key", &key).json(&json!({"composeId": id, "env": dotenv_render(&merged)}))).await.map_err(|e| format!("Dokploy compose saveEnvironment failed: {}", e))?;
            if config.get("redeploy").and_then(Value::as_bool).unwrap_or(false) { req(client.post(format!("{}/api/compose.redeploy", base)).header("x-api-key", &key).json(&json!({"composeId": id}))).await.map_err(|e| format!("Dokploy compose redeploy failed: {}", e))?; }
        }
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Dokploy sync{}: {} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, id, created, updated, unchanged, deleted), managed))
}
pub async fn dokploy_test(config: &Value) -> Result<String, String> {
    let (base, key, id, is_app) = dokploy_config(config)?;
    let url = if is_app { format!("{}/api/application.one?applicationId={}", base, form_encode(&id)) } else { format!("{}/api/compose.one?composeId={}", base, form_encode(&id)) };
    let text = req(http_client().get(url).header("x-api-key", &key)).await?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Dokploy invalid response: {}", e))?;
    let count = dotenv_map(value.get("env").and_then(Value::as_str).unwrap_or("")).len();
    Ok(format!("Dokploy connection OK: {} currently has {} environment variables", id, count))
}

// ---------- CapRover ----------
async fn caprover_auth(client: &crate::http::Client, config: &Value) -> Result<(String, String), String> {
    let base = cfg(config, "base_url").trim_end_matches('/').to_string();
    if base.is_empty() { return Err("CapRover requires base_url".into()); }
    let api = format!("{}/api/v2", base);
    let token = { let t = cfg(config, "token"); if !t.is_empty() { t.to_string() } else {
        let password = cfg(config, "password"); if password.is_empty() { return Err("CapRover requires token or password".into()); }
        let text = req(client.post(format!("{}/login", api)).json(&json!({"password": password}))).await.map_err(|e| format!("CapRover login failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("CapRover invalid login response: {}", e))?;
        value.get("data").and_then(|d| d.get("token")).and_then(Value::as_str).ok_or("CapRover login response is missing data.token")?.to_string()
    } };
    Ok((api, token))
}
async fn caprover_apps(client: &crate::http::Client, api: &str, token: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/user/apps/appDefinitions", api)).header("x-captain-auth", token)).await.map_err(|e| format!("CapRover list apps failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("CapRover invalid app list: {}", e))?;
    value.get("data").and_then(|d| d.get("appDefinitions")).and_then(Value::as_array).cloned().ok_or("CapRover invalid app list: missing data.appDefinitions".into())
}
pub async fn caprover_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let client = http_client();
    let (api, token) = caprover_auth(&client, config).await?;
    let mode = sync_mode(config, "caprover")?;
    let dry = is_dry(config);
    let app_name = cfg(config, "app_name").trim();
    if app_name.is_empty() { return Err("CapRover requires app_name".into()); }
    let apps = caprover_apps(&client, &api, &token).await?;
    let app = apps.iter().find(|a| a.get("appName").and_then(Value::as_str) == Some(app_name)).ok_or_else(|| format!("CapRover app {:?} not found", app_name))?;
    let current: HashMap<String, String> = app.get("envVars").and_then(Value::as_array).map(|items| items.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect()).unwrap_or_default();
    let notes: HashMap<String, String> = app.get("envVars").and_then(Value::as_array).map(|items| items.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), v.get("notes").and_then(Value::as_str).unwrap_or("").to_string()))).collect()).unwrap_or_default();
    let desired = trigger_desired(config, secrets);
    if let Some(bad) = env_names_ok(&desired.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()) { return Err(format!("CapRover invalid environment variable names: {}", bad)); }
    let (merged, created, updated, unchanged, deleted) = merge_pairs(&current, &desired, previous_managed, mode == "mirror");
    if !dry {
        let env_vars: Vec<Value> = merged.iter().map(|(k, v)| json!({"key": k, "value": v, "notes": notes.get(k).cloned().unwrap_or_default()})).collect();
        let mut body = app.clone(); body["envVars"] = json!(env_vars);
        req(client.post(format!("{}/user/apps/appDefinitions/update/", api)).header("x-captain-auth", &token).json(&body)).await.map_err(|e| format!("CapRover update failed: {}", e))?;
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("CapRover sync{}: app {} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, app_name, created, updated, unchanged, deleted), managed))
}
pub async fn caprover_test(config: &Value) -> Result<String, String> {
    let client = http_client(); let (api, token) = caprover_auth(&client, config).await?;
    let apps = caprover_apps(&client, &api, &token).await?;
    Ok(format!("CapRover connection OK: {} app(s) visible", apps.len()))
}

// ---------- Portainer ----------
fn portainer_auth(config: &Value) -> Result<(String, String), String> {
    let base = cfg(config, "base_url").trim_end_matches('/').to_string();
    let key = cfg(config, "api_key").trim();
    if base.is_empty() || key.is_empty() { return Err("Portainer requires base_url and api_key".into()); }
    Ok((base, key.to_string()))
}
async fn portainer_stacks(client: &crate::http::Client, base: &str, key: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/api/stacks", base)).header("X-API-Key", key)).await.map_err(|e| format!("Portainer list stacks failed: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Portainer invalid stack list: {}", e))
}
pub async fn portainer_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, key) = portainer_auth(config)?;
    let mode = sync_mode(config, "portainer")?;
    let dry = is_dry(config);
    let client = http_client();
    let stacks = portainer_stacks(&client, &base, &key).await?;
    let wanted_id = config_i64(config, "stack_id");
    let wanted_name = cfg(config, "stack_name");
    let stack = stacks.iter().find(|s| (wanted_id.is_some() && s.get("Id").and_then(Value::as_i64) == wanted_id) || (!wanted_name.is_empty() && s.get("Name").and_then(Value::as_str) == Some(wanted_name))).ok_or("Portainer stack not found")?;
    let id = stack.get("Id").and_then(Value::as_i64).ok_or("Portainer stack has no Id")?;
    let endpoint_id = config_i64(config, "endpoint_id").or_else(|| stack.get("EndpointId").and_then(Value::as_i64)).ok_or("Portainer requires endpoint_id (or a stack with EndpointId)")?;
    // The list response is not guaranteed to include Env; read the stack detail
    // so unrelated variables are preserved rather than wiped.
    let detail_text = req(client.get(format!("{}/api/stacks/{}", base, id)).header("X-API-Key", &key)).await.map_err(|e| format!("Portainer read stack failed: {}", e))?;
    let detail: Value = serde_json::from_str(&detail_text).map_err(|e| format!("Portainer invalid stack response: {}", e))?;
    let current: HashMap<String, String> = detail.get("Env").and_then(Value::as_array).map(|items| items.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect()).unwrap_or_default();
    let desired = trigger_desired(config, secrets);
    if let Some(bad) = env_names_ok(&desired.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()) { return Err(format!("Portainer invalid environment variable names: {}", bad)); }
    let (merged, created, updated, unchanged, deleted) = merge_pairs(&current, &desired, previous_managed, mode == "mirror");
    if !dry {
        let file_text = req(client.get(format!("{}/api/stacks/{}/file", base, id)).header("X-API-Key", &key)).await.map_err(|e| format!("Portainer read stack file failed: {}", e))?;
        let file: Value = serde_json::from_str(&file_text).map_err(|e| format!("Portainer invalid stack file response: {}", e))?;
        let env_json: Vec<Value> = merged.iter().map(|(k, v)| json!({"name": k, "value": v})).collect();
        let body = json!({"StackFileContent": file.get("StackFileContent").and_then(Value::as_str).unwrap_or(""), "Env": env_json, "Prune": false, "PullImage": false});
        req(client.put(format!("{}/api/stacks/{}?endpointId={}", base, id, endpoint_id)).header("X-API-Key", &key).json(&body)).await.map_err(|e| format!("Portainer update stack failed: {}", e))?;
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Portainer sync{}: stack {} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, id, created, updated, unchanged, deleted), managed))
}
pub async fn portainer_test(config: &Value) -> Result<String, String> {
    let (base, key) = portainer_auth(config)?;
    let stacks = portainer_stacks(&http_client(), &base, &key).await?;
    Ok(format!("Portainer connection OK: {} stack(s) visible", stacks.len()))
}

// ---------- Docker Swarm ----------
fn docker_client(config: &Value) -> Result<crate::http::Client, String> {
    let cert = cfg(config, "client_cert"); let key = cfg(config, "client_key"); let ca = cfg(config, "ca_cert");
    if !cert.is_empty() || !key.is_empty() || !ca.is_empty() {
        #[cfg(target_arch = "wasm32")]
        { let _ = (cert, key, ca); return Err("Docker client certificates are unavailable on Workers".into()); }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none());
            if !cert.is_empty() || !key.is_empty() {
                if cert.is_empty() { return Err("Docker requires both client_cert and client_key".into()); }
                if key.is_empty() { return Err("Docker requires both client_cert and client_key".into()); }
                let identity = reqwest::Identity::from_pem(format!("{}\n{}", cert, key).as_bytes()).map_err(|e| format!("Docker client certificate is invalid: {}", e))?;
                builder = builder.identity(identity);
            }
            if !ca.is_empty() { builder = builder.add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).map_err(|e| format!("Docker CA certificate is invalid: {}", e))?); }
            if config.get("insecure").and_then(Value::as_bool).unwrap_or(false) { builder = builder.danger_accept_invalid_certs(true); }
            return builder.build().map_err(|e| e.to_string());
        }
    }
    Ok(http_client())
}
fn docker_base(config: &Value) -> Result<String, String> {
    let raw = cfg(config, "api_url").trim_end_matches('/');
    if raw.is_empty() { return Err("Docker requires api_url (the Docker Engine endpoint, for example https://host:2376)".into()); }
    let version = { let v = cfg(config, "api_version"); if v.is_empty() { "v1.47" } else { v } };
    let last = raw.rsplit('/').next().unwrap_or("");
    let versioned = last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit() || c == '.');
    Ok(if versioned { raw.to_string() } else { format!("{}/{}", raw, version) })
}
pub async fn docker_swarm_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let base = docker_base(config)?;
    let client = docker_client(config)?;
    let mode = sync_mode(config, "docker_swarm")?;
    let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(name, _)| name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))) { return Err(format!("Docker secret names must be 1-64 characters of letters, digits, underscore, dot or dash: {:?}", name)); }
    let text = req(client.get(format!("{}/secrets", base))).await.map_err(|e| format!("Docker list secrets failed: {}", e))?;
    let list: Vec<Value> = serde_json::from_str(&text).map_err(|e| format!("Docker invalid secret list: {}", e))?;
    let by_name: HashMap<String, String> = list.iter().filter_map(|s| Some((s.get("Spec")?.get("Name")?.as_str()?.to_string(), s.get("ID")?.as_str()?.to_string()))).collect();
    let created = desired.iter().filter(|(name, _)| !by_name.contains_key(name)).count();
    let replaced = desired.len() - created;
    let mut deleted = 0;
    if !dry {
        for (name, value) in &desired {
            if let Some(id) = by_name.get(name) {
                req(client.delete(format!("{}/secrets/{}", base, id))).await.map_err(|e| format!("Docker delete {} before recreate failed: {}", name, e))?;
            }
            req(client.post(format!("{}/secrets/create", base)).json(&json!({"Name": name, "Labels": {"com.openwarp.managed": "true"}, "Data": openwarp_crypto::b64(value.as_bytes())}))).await.map_err(|e| format!("Docker create {} failed: {}", name, e))?;
        }
        if mode == "mirror" {
            for name in previous_managed {
                if desired.iter().any(|(n, _)| n == name) { continue; }
                if let Some(id) = by_name.get(name) {
                    req(client.delete(format!("{}/secrets/{}", base, id))).await.map_err(|e| format!("Docker delete {} failed: {}", name, e))?;
                    deleted += 1;
                }
            }
        }
    } else { deleted = previous_managed.iter().filter(|name| !desired.iter().any(|(n, _)| n == *name) && by_name.contains_key(*name)).count(); }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Docker Swarm sync{}: created={} replaced={} deleted={} (Docker secrets are immutable, so existing values are deleted and recreated)", if dry { " (dry-run)" } else { "" }, created, replaced, deleted), managed))
}
pub async fn docker_swarm_test(config: &Value) -> Result<String, String> {
    let base = docker_base(config)?; let client = docker_client(config)?;
    let text = req(client.get(format!("{}/_ping", base))).await.map_err(|e| format!("Docker Engine ping failed: {}", e))?;
    Ok(format!("Docker Engine connection OK: {}", text.trim()))
}

// ---------- Bitbucket Pipelines ----------
fn auth_value(config: &Value) -> Result<String, String> {
    let token = cfg(config, "token");
    let password = cfg(config, "password");
    let user = cfg(config, "username");
    let secret = if password.is_empty() { token } else { password };
    if secret.is_empty() { return Err("token is required".into()); }
    if user.is_empty() { Ok(format!("Bearer {}", secret)) } else { Ok(format!("Basic {}", openwarp_crypto::b64(format!("{}:{}", user, secret).as_bytes()))) }
}
async fn bitbucket_list(client: &crate::http::Client, base: &str, workspace: &str, repo: &str, auth: &str) -> Result<Vec<Value>, String> {
    let mut url = format!("{}/repositories/{}/{}/pipelines_config/variables/?pagelen=100", base, enc(workspace), enc(repo));
    let mut out = Vec::new();
    loop {
        let text = req(client.get(&url).header("Authorization", auth)).await.map_err(|e| format!("Bitbucket list failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Bitbucket invalid variable list: {}", e))?;
        if let Some(items) = value.get("values").and_then(Value::as_array) { out.extend(items.iter().cloned()); }
        let next = value.get("next").and_then(Value::as_str).unwrap_or("").to_string();
        if next.is_empty() { break; }
        url = next;
    }
    Ok(out)
}
pub async fn bitbucket_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let base = base(config, "https://api.bitbucket.org/2.0");
    let (workspace, repo) = (cfg(config, "workspace"), cfg(config, "repo_slug"));
    if workspace.is_empty() || repo.is_empty() { return Err("Bitbucket requires workspace and repo_slug".into()); }
    let auth = auth_value(config)?; let mode = sync_mode(config, "bitbucket")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| n.is_empty() || n.len() > 255 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))) { return Err(format!("Bitbucket variable names must be 1-255 letters, digits, underscore or dash: {:?}", name)); }
    let client = http_client(); let root = format!("{}/repositories/{}/{}/pipelines_config/variables", base, enc(workspace), enc(repo));
    let remote = bitbucket_list(&client, &base, workspace, repo, &auth).await?;
    let by_key: HashMap<String, (String, Option<String>)> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), (v.get("uuid")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).map(str::to_string))))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            match by_key.get(name) {
                Some((_, Some(old))) if old == value => unchanged += 1,
                Some((uuid, _)) => { req(client.put(format!("{}/{}", root, uuid)).header("Authorization", &auth).json(&json!({"key": name, "value": value, "secured": true}))).await.map_err(|e| format!("Bitbucket update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(format!("{}/", root)).header("Authorization", &auth).json(&json!({"key": name, "value": value, "secured": true}))).await.map_err(|e| format!("Bitbucket create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" {
            for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.contains_key(name) { continue; }
                if let Some((uuid, _)) = by_key.get(name) { req(client.delete(format!("{}/{}", root, uuid)).header("Authorization", &auth)).await.map_err(|e| format!("Bitbucket delete {} failed: {}", name, e))?; } }
        }
    } else { for (name, value) in &desired { match by_key.get(name) { Some((_, Some(old))) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Bitbucket sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn bitbucket_test(config: &Value) -> Result<String, String> {
    let base = base(config, "https://api.bitbucket.org/2.0");
    let (workspace, repo) = (cfg(config, "workspace"), cfg(config, "repo_slug"));
    if workspace.is_empty() || repo.is_empty() { return Err("Bitbucket requires workspace and repo_slug".into()); }
    let list = bitbucket_list(&http_client(), &base, workspace, repo, &auth_value(config)?).await?;
    Ok(format!("Bitbucket connection OK: {} variable(s) visible", list.len()))
}

// ---------- CircleCI ----------
async fn circleci_list(client: &crate::http::Client, base: &str, slug: &str, token: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/project/{}/envvar", base, slug.trim_matches('/'))).header("Circle-Token", token)).await.map_err(|e| format!("CircleCI list failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("CircleCI invalid env var list: {}", e))?;
    Ok(value.get("items").and_then(Value::as_array).cloned().unwrap_or_default())
}
pub async fn circleci_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let base = base(config, "https://circleci.com/api/v2"); let slug = cfg(config, "project_slug"); let token = cfg(config, "token");
    if slug.is_empty() || token.is_empty() { return Err("CircleCI requires project_slug and token".into()); }
    let mode = sync_mode(config, "circleci")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| n.is_empty() || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))) { return Err(format!("CircleCI variable names must use letters, digits, underscore or dash: {:?}", name)); }
    let client = http_client(); let root = format!("{}/project/{}/envvar", base, slug.trim_matches('/'));
    let remote = circleci_list(&client, &base, slug, token).await?;
    let names: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect();
    let (mut created, mut updated) = (0, 0);
    if !dry {
        for (name, value) in &desired {
            if names.contains_key(name) { req(client.delete(format!("{}/{}", root, enc(name))).header("Circle-Token", token)).await.map_err(|e| format!("CircleCI delete {} before update failed: {}", name, e))?; updated += 1; }
            else { created += 1; }
            req(client.post(&root).header("Circle-Token", token).json(&json!({"name": name, "value": value}))).await.map_err(|e| format!("CircleCI write {} failed: {}", name, e))?;
        }
        if mode == "mirror" {
            for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !names.contains_key(name) { continue; }
                req(client.delete(format!("{}/{}", root, enc(name))).header("Circle-Token", token)).await.map_err(|e| format!("CircleCI delete {} failed: {}", name, e))?; }
        }
    } else { for (name, _) in &desired { if names.contains_key(name) { updated += 1; } else { created += 1; } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && names.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("CircleCI sync{}: created={} updated={} deleted={} (existing values are recreated because the API has no update call)", if dry { " (dry-run)" } else { "" }, created, updated, deleted), managed))
}
pub async fn circleci_test(config: &Value) -> Result<String, String> {
    let base = base(config, "https://circleci.com/api/v2"); let slug = cfg(config, "project_slug"); let token = cfg(config, "token");
    if slug.is_empty() || token.is_empty() { return Err("CircleCI requires project_slug and token".into()); }
    let list = circleci_list(&http_client(), &base, slug, token).await?;
    Ok(format!("CircleCI connection OK: {} environment variable(s) visible", list.len()))
}

// ---------- TeamCity ----------
fn teamcity_base(config: &Value) -> Result<String, String> {
    let raw = cfg(config, "base_url").trim_end_matches('/');
    if raw.is_empty() { return Err("TeamCity requires base_url".into()); }
    Ok(if raw.ends_with("/app/rest") { raw.to_string() } else { format!("{}/app/rest", raw) })
}
fn teamcity_scope(config: &Value) -> (String, String) {
    if !cfg(config, "build_type_locator").is_empty() { ("buildTypes".into(), cfg(config, "build_type_locator").to_string()) }
    else { ("projects".into(), { let p = cfg(config, "project_locator"); if p.is_empty() { "_Root".to_string() } else { p.to_string() } }) }
}
async fn teamcity_list(client: &crate::http::Client, base: &str, auth: &str, kind: &str, locator: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/{}/{}/parameters", base, kind, enc(locator))).header("Authorization", auth).header("Accept", "application/json")).await.map_err(|e| format!("TeamCity list parameters failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("TeamCity invalid parameter list: {}", e))?;
    Ok(value.get("property").and_then(Value::as_array).cloned().unwrap_or_default())
}
pub async fn teamcity_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let base = teamcity_base(config)?; let auth = auth_value(config)?; let (kind, locator) = teamcity_scope(config);
    let mode = sync_mode(config, "teamcity")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let root = format!("{}/{}/{}/parameters", base, kind, enc(&locator));
    let remote = teamcity_list(&client, &base, &auth, &kind, &locator).await?;
    let by_name: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            match by_name.get(name) {
                Some(old) if old == value => unchanged += 1,
                Some(_) => { req(client.put(format!("{}/{}", root, enc(name))).header("Authorization", &auth).json(&json!({"name": name, "value": value}))).await.map_err(|e| format!("TeamCity update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(&root).header("Authorization", &auth).json(&json!({"name": name, "value": value}))).await.map_err(|e| format!("TeamCity create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_name.contains_key(name) { continue; }
            req(client.delete(format!("{}/{}", root, enc(name))).header("Authorization", &auth)).await.map_err(|e| format!("TeamCity delete {} failed: {}", name, e))?; } }
    } else { for (name, value) in &desired { match by_name.get(name) { Some(old) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("TeamCity sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn teamcity_test(config: &Value) -> Result<String, String> {
    let base = teamcity_base(config)?; let auth = auth_value(config)?; let (kind, locator) = teamcity_scope(config);
    let list = teamcity_list(&http_client(), &base, &auth, &kind, &locator).await?;
    Ok(format!("TeamCity connection OK: {} parameter(s) visible", list.len()))
}

// ---------- Travis CI ----------
async fn travis_list(client: &crate::http::Client, base: &str, slug: &str, token: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/repo/{}/env_vars", base, slug)).header("Travis-API-Version", "3").header("Authorization", format!("token {}", token))).await.map_err(|e| format!("Travis CI list failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Travis CI invalid env var list: {}", e))?;
    Ok(value.get("env_vars").and_then(Value::as_array).cloned().unwrap_or_default())
}
pub async fn travisci_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let base = base(config, "https://api.travis-ci.com"); let slug = enc(cfg(config, "repo")); let token = cfg(config, "token");
    if cfg(config, "repo").is_empty() || token.is_empty() { return Err("Travis CI requires repo (owner/name) and token".into()); }
    let mode = sync_mode(config, "travisci")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let root = format!("{}/repo/{}/env_vars", base, slug);
    let remote = travis_list(&client, &base, &slug, token).await?;
    let by_name: HashMap<String, (String, Option<String>)> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), (v.get("id")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).map(str::to_string))))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            match by_name.get(name) {
                Some((_, Some(old))) if old == value => unchanged += 1,
                Some((id, _)) => { req(client.patch(format!("{}/{}", root, id)).header("Travis-API-Version", "3").header("Authorization", format!("token {}", token)).json(&json!({"env_var": {"name": name, "value": value, "public": false}}))).await.map_err(|e| format!("Travis CI update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(&root).header("Travis-API-Version", "3").header("Authorization", format!("token {}", token)).json(&json!({"env_var": {"name": name, "value": value, "public": false}}))).await.map_err(|e| format!("Travis CI create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_name.contains_key(name) { continue; }
            if let Some((id, _)) = by_name.get(name) { req(client.delete(format!("{}/{}", root, id)).header("Travis-API-Version", "3").header("Authorization", format!("token {}", token))).await.map_err(|e| format!("Travis CI delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { match by_name.get(name) { Some((_, Some(old))) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Travis CI sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn travisci_test(config: &Value) -> Result<String, String> {
    let base = base(config, "https://api.travis-ci.com"); let slug = enc(cfg(config, "repo")); let token = cfg(config, "token");
    if cfg(config, "repo").is_empty() || token.is_empty() { return Err("Travis CI requires repo (owner/name) and token".into()); }
    let list = travis_list(&http_client(), &base, &slug, token).await?;
    Ok(format!("Travis CI connection OK: {} environment variable(s) visible", list.len()))
}

// ---------- Terraform Cloud ----------
async fn tfcloud_list(client: &crate::http::Client, base: &str, token: &str, workspace_id: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(format!("{}/workspaces/{}/vars", base, workspace_id)).bearer_auth(token)).await.map_err(|e| format!("Terraform Cloud list failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Terraform Cloud invalid variable list: {}", e))?;
    Ok(value.get("data").and_then(Value::as_array).cloned().unwrap_or_default())
}
pub async fn terraform_cloud_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let base = base(config, "https://app.terraform.io/api/v2"); let token = cfg(config, "token"); let workspace_id = cfg(config, "workspace_id");
    if token.is_empty() || workspace_id.is_empty() { return Err("Terraform Cloud requires token and workspace_id".into()); }
    let category = { let c = cfg(config, "category"); if c.is_empty() { "env" } else { c } };
    let sensitive = config.get("sensitive").and_then(Value::as_bool).unwrap_or(true);
    let mode = sync_mode(config, "terraform_cloud")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let root = format!("{}/workspaces/{}/vars", base, workspace_id);
    let remote = tfcloud_list(&client, &base, token, workspace_id).await?;
    let by_key: HashMap<String, (String, Option<String>)> = remote.iter().filter(|v| v.get("attributes").and_then(|a| a.get("category")).and_then(Value::as_str) == Some(category)).filter_map(|v| Some((v.get("attributes")?.get("key")?.as_str()?.to_string(), (v.get("id")?.as_str()?.to_string(), v.get("attributes").and_then(|a| a.get("value")).and_then(Value::as_str).map(str::to_string))))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            let attributes = json!({"key": name, "value": value, "category": category, "sensitive": sensitive});
            match by_key.get(name) {
                Some((_, Some(old))) if old == value => unchanged += 1,
                Some((id, _)) => { req(client.patch(format!("{}/vars/{}", base, id)).bearer_auth(token).json(&json!({"data": {"id": id, "type": "vars", "attributes": attributes}}))).await.map_err(|e| format!("Terraform Cloud update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(&root).bearer_auth(token).json(&json!({"data": {"type": "vars", "attributes": attributes}}))).await.map_err(|e| format!("Terraform Cloud create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.contains_key(name) { continue; }
            if let Some((id, _)) = by_key.get(name) { req(client.delete(format!("{}/vars/{}", base, id)).bearer_auth(token)).await.map_err(|e| format!("Terraform Cloud delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { match by_key.get(name) { Some((_, Some(old))) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Terraform Cloud sync{}: category={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, category, created, updated, unchanged, deleted), managed))
}
pub async fn terraform_cloud_test(config: &Value) -> Result<String, String> {
    let base = base(config, "https://app.terraform.io/api/v2"); let token = cfg(config, "token"); let workspace_id = cfg(config, "workspace_id");
    if token.is_empty() || workspace_id.is_empty() { return Err("Terraform Cloud requires token and workspace_id".into()); }
    let list = tfcloud_list(&http_client(), &base, token, workspace_id).await?;
    Ok(format!("Terraform Cloud connection OK: {} variable(s) visible", list.len()))
}

// ---------- Qovery ----------
fn qovery_root(config: &Value) -> Result<(String, String), String> {
    let base = base(config, "https://api.qovery.com"); let token = cfg(config, "token");
    let (org, project, env) = (cfg(config, "organization_id"), cfg(config, "project_id"), cfg(config, "environment_id"));
    if token.is_empty() || org.is_empty() || project.is_empty() || env.is_empty() { return Err("Qovery requires token, organization_id, project_id and environment_id".into()); }
    Ok((format!("{}/organization/{}/project/{}/environment/{}/variable", base, org, project, env), token.to_string()))
}
async fn qovery_list(client: &crate::http::Client, root: &str, token: &str) -> Result<Vec<Value>, String> {
    let text = req(client.get(root).bearer_auth(token)).await.map_err(|e| format!("Qovery list failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Qovery invalid variable list: {}", e))?;
    Ok(value.get("results").and_then(Value::as_array).or_else(|| value.as_array()).cloned().unwrap_or_default())
}
pub async fn qovery_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (root, token) = qovery_root(config)?; let mode = sync_mode(config, "qovery")?; let dry = is_dry(config);
    let scope = { let s = cfg(config, "scope"); if s.is_empty() { "ENV" } else { s } };
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let remote = qovery_list(&client, &root, &token).await?;
    let by_key: HashMap<String, (String, Option<String>)> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), (v.get("id")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).map(str::to_string))))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            match by_key.get(name) {
                Some((_, Some(old))) if old == value => unchanged += 1,
                Some((id, _)) => { req(client.put(format!("{}/{}", root, id)).bearer_auth(&token).json(&json!({"key": name, "value": value, "scope": scope}))).await.map_err(|e| format!("Qovery update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(&root).bearer_auth(&token).json(&json!({"key": name, "value": value, "scope": scope}))).await.map_err(|e| format!("Qovery create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.contains_key(name) { continue; }
            if let Some((id, _)) = by_key.get(name) { req(client.delete(format!("{}/{}", root, id)).bearer_auth(&token)).await.map_err(|e| format!("Qovery delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { match by_key.get(name) { Some((_, Some(old))) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Qovery sync{}: scope={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, scope, created, updated, unchanged, deleted), managed))
}
pub async fn qovery_test(config: &Value) -> Result<String, String> {
    let (root, token) = qovery_root(config)?;
    let list = qovery_list(&http_client(), &root, &token).await?;
    Ok(format!("Qovery connection OK: {} variable(s) visible", list.len()))
}

// ---------- Laravel Forge ----------
fn config_text(config: &Value, key: &str) -> String {
    match config.get(key) {
        Some(Value::String(value)) => value.clone(),
        Some(value) if value.is_number() => value.to_string(),
        _ => String::new(),
    }
}
fn forge_root(config: &Value) -> Result<(String, String), String> {
    let base = base(config, "https://forge.laravel.com/api"); let token = cfg(config, "token");
    let (org, server, site) = (cfg(config, "organization"), config_text(config, "server_id"), config_text(config, "site_id"));
    if token.is_empty() || org.is_empty() || server.is_empty() || site.is_empty() { return Err("Laravel Forge requires token, organization, server_id and site_id".into()); }
    Ok((format!("{}/orgs/{}/servers/{}/sites/{}/environment", base, enc(org), enc(&server), enc(&site)), token.to_string()))
}
async fn forge_env(client: &crate::http::Client, root: &str, token: &str) -> Result<String, String> {
    let text = req(client.get(root).bearer_auth(token).header("Accept", "application/vnd.api+json")).await.map_err(|e| format!("Laravel Forge read environment failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Laravel Forge invalid environment response: {}", e))?;
    Ok(value.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("content")).and_then(Value::as_str).unwrap_or("").to_string())
}
pub async fn laravel_forge_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (root, token) = forge_root(config)?; let mode = sync_mode(config, "laravel_forge")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(_, v)| v.contains('\n') || v.contains('\r')) { return Err(format!("Laravel Forge env values cannot contain line breaks: {:?}", name)); }
    let client = http_client(); let current = dotenv_map(&forge_env(&client, &root, &token).await?);
    let (merged, created, updated, unchanged, deleted) = merge_pairs(&current, &desired, previous_managed, mode == "mirror");
    if !dry { req(client.put(&root).bearer_auth(&token).json(&json!({"environment": dotenv_render(&merged)}))).await.map_err(|e| format!("Laravel Forge update failed: {}", e))?; }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Laravel Forge sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn laravel_forge_test(config: &Value) -> Result<String, String> {
    let (root, token) = forge_root(config)?;
    let env = forge_env(&http_client(), &root, &token).await?;
    Ok(format!("Laravel Forge connection OK: environment has {} variable(s)", dotenv_map(&env).len()))
}

// ---------- OpenWarp to OpenWarp ----------
fn openwarp_remote(config: &Value) -> Result<(String, String, String), String> {
    let base = cfg(config, "base_url").trim_end_matches('/').to_string(); let token = cfg(config, "token"); let env = cfg(config, "env_id");
    if base.is_empty() || token.is_empty() || env.is_empty() { return Err("OpenWarp sync requires base_url, token and env_id".into()); }
    Ok((base, token.to_string(), env.to_string()))
}
async fn openwarp_list(client: &crate::http::Client, base: &str, token: &str, env: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut offset = 0;
    loop {
        let text = req(client.get(format!("{}/api/envs/{}/secrets?limit=1000&offset={}", base, env, offset)).bearer_auth(token)).await.map_err(|e| format!("OpenWarp list secrets failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("OpenWarp invalid secret list: {}", e))?;
        let page = value.get("secrets").and_then(Value::as_array).cloned().unwrap_or_default();
        let total = value.get("total").and_then(Value::as_u64).unwrap_or(0) as usize;
        out.extend(page);
        offset += 1000;
        if out.len() >= total || offset > 100_000 { break; }
    }
    Ok(out)
}
pub async fn openwarp_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token, env) = openwarp_remote(config)?; let mode = sync_mode(config, "openwarp")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let remote = openwarp_list(&client, &base, &token, &env).await?;
    let by_key: HashMap<String, (String, Option<String>)> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), (v.get("id")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).map(str::to_string))))).collect();
    let mut unchanged = 0;
    if !dry {
        let list: Vec<Value> = desired.iter().map(|(k, v)| json!({"key": k, "value": v, "path": "/"})).collect();
        if !list.is_empty() { req(client.put(format!("{}/api/envs/{}/secrets", base, env)).bearer_auth(&token).json(&json!({"secrets": list}))).await.map_err(|e| format!("OpenWarp deploy failed: {}", e))?; }
        for (name, value) in &desired { if by_key.get(name).and_then(|(_, v)| v.as_deref()) == Some(value.as_str()) { unchanged += 1; } }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.contains_key(name) { continue; }
            if let Some((id, _)) = by_key.get(name) { req(client.delete(format!("{}/api/secrets/{}", base, id)).bearer_auth(&token)).await.map_err(|e| format!("OpenWarp delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { if by_key.get(name).and_then(|(_, v)| v.as_deref()) == Some(value.as_str()) { unchanged += 1; } } }
    let created = desired.iter().filter(|(n, _)| !by_key.contains_key(n)).count();
    let updated_existing = desired.len() - created - unchanged;
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("OpenWarp sync{}: env={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, env, created, updated_existing, unchanged, deleted), managed))
}
pub async fn openwarp_test(config: &Value) -> Result<String, String> {
    let (base, token, env) = openwarp_remote(config)?;
    let list = openwarp_list(&http_client(), &base, &token, &env).await?;
    Ok(format!("OpenWarp connection OK: environment {} currently has {} secret(s)", env, list.len()))
}

// ---------- Devin ----------
fn devin_parts(config: &Value) -> Result<(String, String, String), String> {
    let base = base(config, "https://api.devin.ai"); let token = cfg(config, "token"); let org = cfg(config, "org_id");
    if token.is_empty() || org.is_empty() { return Err("Devin requires token and org_id".into()); }
    Ok((base, token.to_string(), org.to_string()))
}
async fn devin_list(client: &crate::http::Client, base: &str, token: &str, org: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut after = String::new();
    loop {
        let mut url = format!("{}/v3/organizations/{}/secrets?first=200", base, enc(org));
        if !after.is_empty() { url.push_str(&format!("&after={}", enc(&after))); }
        let text = req(client.get(&url).bearer_auth(token)).await.map_err(|e| format!("Devin list secrets failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Devin invalid secret list: {}", e))?;
        if let Some(items) = value.get("items").and_then(Value::as_array) { out.extend(items.iter().cloned()); }
        let next = value.get("end_cursor").and_then(Value::as_str).unwrap_or("").to_string();
        if !value.get("has_next_page").and_then(Value::as_bool).unwrap_or(false) || next.is_empty() { break; }
        after = next;
    }
    Ok(out)
}
pub async fn devin_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token, org) = devin_parts(config)?; let mode = sync_mode(config, "devin")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let root = format!("{}/v3/organizations/{}/secrets", base, enc(&org));
    let remote = devin_list(&client, &base, &token, &org).await?;
    let by_key: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), v.get("secret_id")?.as_str()?.to_string()))).collect();
    let (mut created, mut updated) = (0, 0);
    if !dry {
        for (name, value) in &desired {
            if let Some(id) = by_key.get(name) { req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Devin delete {} before update failed: {}", name, e))?; updated += 1; }
            else { created += 1; }
            req(client.post(&root).bearer_auth(&token).json(&json!({"type": "key-value", "key": name, "value": value, "is_sensitive": true}))).await.map_err(|e| format!("Devin create {} failed: {}", name, e))?;
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.contains_key(name) { continue; }
            if let Some(id) = by_key.get(name) { req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Devin delete {} failed: {}", name, e))?; } } }
    } else { for (name, _) in &desired { if by_key.contains_key(name) { updated += 1; } else { created += 1; } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Devin sync{}: created={} updated={} deleted={} (existing secrets are recreated because values are not readable)", if dry { " (dry-run)" } else { "" }, created, updated, deleted), managed))
}
pub async fn devin_test(config: &Value) -> Result<String, String> {
    let (base, token, org) = devin_parts(config)?;
    let list = devin_list(&http_client(), &base, &token, &org).await?;
    Ok(format!("Devin connection OK: {} organization secret(s) visible", list.len()))
}

// ---------- Cloudflare Secrets Store ----------
fn cf_store_root(config: &Value) -> Result<(String, String), String> {
    let base = base(config, "https://api.cloudflare.com/client/v4"); let token = cfg(config, "token");
    let (account, store) = (cfg(config, "account_id"), cfg(config, "store_id"));
    if token.is_empty() || account.is_empty() || store.is_empty() { return Err("Cloudflare Secrets Store requires token, account_id and store_id".into()); }
    Ok((format!("{}/accounts/{}/secrets_store/stores/{}/secrets", base, enc(account), enc(store)), token.to_string()))
}
async fn cf_store_list(client: &crate::http::Client, root: &str, token: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut page = 1;
    loop {
        let text = req(client.get(format!("{}?per_page=100&page={}", root, page)).bearer_auth(token)).await.map_err(|e| format!("Cloudflare Secrets Store list failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Cloudflare Secrets Store invalid list: {}", e))?;
        if let Some(items) = value.get("result").and_then(Value::as_array) { out.extend(items.iter().filter(|v| v.get("status").and_then(Value::as_str) != Some("deleted")).cloned()); }
        let pages = value.get("result_info").and_then(|i| i.get("total_pages")).and_then(Value::as_u64).unwrap_or(1);
        if page as u64 >= pages { break; }
        page += 1;
    }
    Ok(out)
}
pub async fn cloudflare_secrets_store_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (root, token) = cf_store_root(config)?; let mode = sync_mode(config, "cloudflare_secrets_store")?; let dry = is_dry(config);
    let scopes = config.get("scopes").cloned().unwrap_or(json!(["workers"]));
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| n.is_empty() || n.len() > 255 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))) { return Err(format!("Cloudflare Secrets Store names must use letters, digits, hyphens or underscores: {:?}", name)); }
    if let Some((name, _)) = desired.iter().find(|(_, v)| v.len() > 65536) { return Err(format!("Cloudflare Secrets Store values are limited to 64 KiB: {:?}", name)); }
    let client = http_client(); let remote = cf_store_list(&client, &root, &token).await?;
    let by_name: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("id")?.as_str()?.to_string()))).collect();
    let (mut created, mut updated) = (0, 0);
    if !dry {
        for (name, value) in &desired {
            if let Some(id) = by_name.get(name) { req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Cloudflare Secrets Store delete {} before update failed: {}", name, e))?; updated += 1; }
            else { created += 1; }
            req(client.post(&root).bearer_auth(&token).json(&json!([{"name": name, "value": value, "scopes": scopes}]))).await.map_err(|e| format!("Cloudflare Secrets Store create {} failed: {}", name, e))?;
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_name.contains_key(name) { continue; }
            if let Some(id) = by_name.get(name) { req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Cloudflare Secrets Store delete {} failed: {}", name, e))?; } } }
    } else { for (name, _) in &desired { if by_name.contains_key(name) { updated += 1; } else { created += 1; } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Cloudflare Secrets Store sync{}: created={} updated={} deleted={} (values are write-only, so existing secrets are recreated)", if dry { " (dry-run)" } else { "" }, created, updated, deleted), managed))
}
pub async fn cloudflare_secrets_store_test(config: &Value) -> Result<String, String> {
    let (root, token) = cf_store_root(config)?;
    let list = cf_store_list(&http_client(), &root, &token).await?;
    Ok(format!("Cloudflare Secrets Store connection OK: {} secret(s) visible", list.len()))
}

// ---------- Octopus Deploy ----------
fn octopus_root(config: &Value) -> Result<(String, String), String> {
    let raw = cfg(config, "base_url").trim_end_matches('/'); let key = cfg(config, "api_key");
    let (space, project) = (cfg(config, "space_id"), cfg(config, "project_id"));
    if raw.is_empty() || key.is_empty() || project.is_empty() { return Err("Octopus Deploy requires base_url, api_key and project_id".into()); }
    let base = if raw.ends_with("/api") { raw.to_string() } else { format!("{}/api", raw) };
    let space = if space.is_empty() { "Spaces-1" } else { space };
    Ok((format!("{}/{}/projects/{}/variables", base, enc(space), enc(project)), key.to_string()))
}
pub async fn octopus_deploy_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (root, key) = octopus_root(config)?; let mode = sync_mode(config, "octopus_deploy")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client();
    let text = req(client.get(&root).header("X-Octopus-ApiKey", &key)).await.map_err(|e| format!("Octopus Deploy read variables failed: {}", e))?;
    let mut doc: Value = serde_json::from_str(&text).map_err(|e| format!("Octopus Deploy invalid variable response: {}", e))?;
    let (mut created, mut updated, mut unchanged, mut deleted) = (0, 0, 0, 0);
    {
        let variables = doc.get_mut("Variables").and_then(Value::as_array_mut).ok_or("Octopus Deploy response is missing Variables")?;
        let scope = config.get("scope").cloned().unwrap_or(json!({}));
        for (name, value) in &desired {
            if let Some(existing) = variables.iter_mut().find(|v| v.get("Name").and_then(Value::as_str) == Some(name.as_str())) {
                if existing.get("Value").and_then(Value::as_str) == Some(value.as_str()) { unchanged += 1; } else { if !dry { existing["Value"] = json!(value); } updated += 1; }
            } else { if !dry { variables.push(json!({"Name": name, "Value": value, "Scope": scope, "IsEditable": true})); } created += 1; }
        }
        if mode == "mirror" {
            let before = variables.len();
            variables.retain(|v| { let n = v.get("Name").and_then(Value::as_str).unwrap_or(""); desired.iter().any(|(d, _)| d == n) || !previous_managed.iter().any(|p| p == n) });
            deleted = before - variables.len();
        }
    }
    if !dry { req(client.put(&root).header("X-Octopus-ApiKey", &key).json(&doc)).await.map_err(|e| format!("Octopus Deploy update variables failed: {}", e))?; }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Octopus Deploy sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn octopus_deploy_test(config: &Value) -> Result<String, String> {
    let (root, key) = octopus_root(config)?;
    let text = req(http_client().get(&root).header("X-Octopus-ApiKey", &key)).await?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Octopus Deploy invalid response: {}", e))?;
    let count = value.get("Variables").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    Ok(format!("Octopus Deploy connection OK: {} project variable(s) visible", count))
}

// ---------- Azure DevOps variable groups ----------
fn azure_devops_root(config: &Value) -> Result<(String, String), String> {
    let org = cfg(config, "organization"); let project = cfg(config, "project"); let token = cfg(config, "token"); let group = cfg(config, "group_id");
    if org.is_empty() || project.is_empty() || token.is_empty() || group.is_empty() { return Err("Azure DevOps requires organization, project, group_id and token".into()); }
    let base = base(config, &format!("https://dev.azure.com/{}", enc(org)));
    let auth = format!("Basic {}", openwarp_crypto::b64(format!(":{}", token).as_bytes()));
    Ok((format!("{}/{}/_apis/distributedtask/variablegroups/{}?api-version=7.1", base, enc(project), enc(group)), auth))
}
pub async fn azure_devops_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (root, auth) = azure_devops_root(config)?; let mode = sync_mode(config, "azure_devops")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client();
    let text = req(client.get(&root).header("Authorization", &auth).header("Accept", "application/json")).await.map_err(|e| format!("Azure DevOps read variable group failed: {}", e))?;
    let mut doc: Value = serde_json::from_str(&text).map_err(|e| format!("Azure DevOps invalid variable group response: {}", e))?;
    let (mut created, mut updated, mut unchanged, mut deleted) = (0, 0, 0, 0);
    {
        let variables = doc.get_mut("variables").and_then(Value::as_object_mut).ok_or("Azure DevOps response is missing variables")?;
        for (name, value) in &desired {
            match variables.get(name) {
                Some(existing) if existing.get("value").and_then(Value::as_str) == Some(value.as_str()) => unchanged += 1,
                Some(_) => { if !dry { variables.insert(name.clone(), json!({"value": value, "isSecret": true})); } updated += 1; }
                None => { if !dry { variables.insert(name.clone(), json!({"value": value, "isSecret": true})); } created += 1; }
            }
        }
        if mode == "mirror" {
            let before = variables.len();
            variables.retain(|name, _| desired.iter().any(|(d, _)| d == name) || !previous_managed.iter().any(|p| p == name));
            deleted = before - variables.len();
        }
    }
    if !dry { req(client.put(&root).header("Authorization", &auth).header("Content-Type", "application/json").json(&doc)).await.map_err(|e| format!("Azure DevOps update variable group failed: {}", e))?; }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Azure DevOps sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn azure_devops_test(config: &Value) -> Result<String, String> {
    let (root, auth) = azure_devops_root(config)?;
    let text = req(http_client().get(&root).header("Authorization", &auth).header("Accept", "application/json")).await?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Azure DevOps invalid response: {}", e))?;
    let count = value.get("variables").and_then(Value::as_object).map(|o| o.len()).unwrap_or(0);
    Ok(format!("Azure DevOps connection OK: variable group has {} variable(s)", count))
}

// ---------- Cursor Cloud Agents ----------
fn cursor_parts(config: &Value) -> Result<(String, String, String, bool), String> {
    let base = base(config, "https://api.cursor.com"); let token = cfg(config, "token"); let env = cfg(config, "environment_id");
    if token.is_empty() { return Err("Cursor requires token".into()); }
    let is_env = !env.is_empty();
    Ok((base, token.to_string(), env.to_string(), is_env))
}
fn cursor_auth(token: &str) -> String { format!("Basic {}", openwarp_crypto::b64(format!("{}:", token).as_bytes())) }
async fn cursor_list(client: &crate::http::Client, root: &str, token: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut cursor = String::new();
    loop {
        let mut url = format!("{}?limit=100", root);
        if !cursor.is_empty() { url.push_str(&format!("&cursor={}", enc(&cursor))); }
        let text = req(client.get(&url).header("Authorization", cursor_auth(token))).await.map_err(|e| format!("Cursor list secrets failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Cursor invalid secret list: {}", e))?;
        if let Some(items) = value.get("items").or_else(|| value.get("secrets")).and_then(Value::as_array) { out.extend(items.iter().cloned()); }
        else if let Some(items) = value.as_array() { out.extend(items.iter().cloned()); }
        cursor = value.get("nextCursor").or_else(|| value.get("cursor")).and_then(Value::as_str).unwrap_or("").to_string();
        if cursor.is_empty() { break; }
    }
    Ok(out)
}
pub async fn cursor_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token, env, is_env) = cursor_parts(config)?; let mode = sync_mode(config, "cursor")?; let dry = is_dry(config);
    let secret_type = { let t = cfg(config, "secret_type"); if t.is_empty() { "runtime_secret" } else { t } };
    if !matches!(secret_type, "runtime_secret" | "environment_variable") { return Err("Cursor secret_type must be runtime_secret or environment_variable".into()); }
    let repos = config.get("repos").cloned().unwrap_or(json!([]));
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| n.starts_with("CURSOR_") || n.to_uppercase().contains("CURSOR_SANDBOX")) { return Err(format!("Cursor reserves names starting with CURSOR_ or containing CURSOR_SANDBOX: {:?}", name)); }
    let root = if is_env { format!("{}/v1/environments/{}/secrets", base, enc(&env)) } else { format!("{}/v1/team/secrets", base) };
    let client = http_client(); let remote = cursor_list(&client, &root, &token).await?;
    let by_name: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("id").and_then(Value::as_str).unwrap_or("").to_string()))).collect();
    let (mut created, mut updated) = (0, 0);
    if !dry {
        for (name, value) in &desired {
            if by_name.contains_key(name) { updated += 1; } else { created += 1; }
            req(client.put(format!("{}/{}", root, enc(name))).header("Authorization", cursor_auth(&token)).json(&json!({"value": value, "type": secret_type, "repos": repos}))).await.map_err(|e| format!("Cursor set {} failed: {}", name, e))?;
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) { continue; }
            req(client.delete(format!("{}/{}", root, enc(name))).header("Authorization", cursor_auth(&token))).await.map_err(|e| format!("Cursor delete {} failed: {}", name, e))?; } }
    } else { for (name, _) in &desired { if by_name.contains_key(name) { updated += 1; } else { created += 1; } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    let scope = if is_env { format!("environment {}", env) } else { "team".to_string() };
    Ok((format!("Cursor sync{}: {} created={} updated={} deleted={} (values are never returned, so existing names are overwritten)", if dry { " (dry-run)" } else { "" }, scope, created, updated, deleted), managed))
}
pub async fn cursor_test(config: &Value) -> Result<String, String> {
    let (base, token, _, _) = cursor_parts(config)?;
    let list = cursor_list(&http_client(), &format!("{}/v1/secrets", base), &token).await?;
    Ok(format!("Cursor connection OK: {} Cloud Agents secret(s) visible", list.len()))
}

// ---------- Northflank ----------
fn northflank_parts(config: &Value) -> Result<(String, String), String> {
    let base = base(config, "https://api.northflank.com/v1");
    let token = cfg(config, "token"); let project = cfg(config, "project_id"); let group = cfg(config, "secret_group_id");
    if token.is_empty() || project.is_empty() || group.is_empty() { return Err("Northflank requires token, project_id and secret_group_id".into()); }
    Ok((format!("{}/projects/{}/secrets/{}", base, enc(project), enc(group)), token.to_string()))
}
async fn northflank_variables(client: &crate::http::Client, root: &str, token: &str) -> Result<HashMap<String, String>, String> {
    let text = req(client.get(format!("{}/details", root)).bearer_auth(token)).await.map_err(|e| format!("Northflank read secret group failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Northflank invalid secret group response: {}", e))?;
    Ok(value.get("data").and_then(|d| d.get("secrets")).and_then(|s| s.get("variables")).and_then(Value::as_object).map(|vars| vars.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()).unwrap_or_default())
}
pub async fn northflank_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (root, token) = northflank_parts(config)?; let mode = sync_mode(config, "northflank")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let current = northflank_variables(&client, &root, &token).await?;
    let (merged, created, updated, unchanged, deleted) = merge_pairs(&current, &desired, previous_managed, mode == "mirror");
    if !dry {
        let variables: serde_json::Map<String, Value> = merged.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        req(client.patch(&root).bearer_auth(&token).json(&json!({"secrets": {"variables": variables}}))).await.map_err(|e| format!("Northflank update secret group failed: {}", e))?;
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Northflank sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn northflank_test(config: &Value) -> Result<String, String> {
    let (root, token) = northflank_parts(config)?;
    let variables = northflank_variables(&http_client(), &root, &token).await?;
    Ok(format!("Northflank connection OK: secret group has {} variable(s)", variables.len()))
}

// ---------- Spacelift ----------
fn spacelift_endpoint(config: &Value) -> Result<String, String> {
    if !cfg(config, "base_url").is_empty() { return Ok(base(config, "")); }
    let account = cfg(config, "account"); if account.is_empty() { return Err("Spacelift requires base_url or account".into()); }
    Ok(format!("https://{}.app.spacelift.io/graphql", enc(account)))
}
async fn spacelift_auth(client: &crate::http::Client, endpoint: &str, config: &Value) -> Result<String, String> {
    let token = cfg(config, "token"); if !token.is_empty() { return Ok(token.to_string()); }
    let id = cfg(config, "api_key_id"); let secret = cfg(config, "api_key_secret");
    if id.is_empty() || secret.is_empty() { return Err("Spacelift requires token, or api_key_id and api_key_secret".into()); }
    let query = "mutation GetSpaceliftToken($id: ID!, $secret: String!) { apiKeyUser(id: $id, secret: $secret) { jwt } }";
    let data = spacelift_graphql(client, endpoint, None, query, json!({"id": id, "secret": secret})).await?;
    data.get("apiKeyUser").and_then(|u| u.get("jwt")).and_then(Value::as_str).map(str::to_string).ok_or_else(|| "Spacelift did not return a JWT".to_string())
}
async fn spacelift_graphql(client: &crate::http::Client, endpoint: &str, token: Option<&str>, query: &str, variables: Value) -> Result<Value, String> {
    let mut request = client.post(endpoint);
    if let Some(token) = token { request = request.bearer_auth(token); }
    let text = req(request.json(&json!({"query": query, "variables": variables}))).await.map_err(|e| format!("Spacelift GraphQL request failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Spacelift invalid GraphQL response: {}", e))?;
    if let Some(errors) = value.get("errors") { return Err(format!("Spacelift GraphQL error: {}", errors)); }
    Ok(value.get("data").cloned().unwrap_or(json!({})))
}
async fn spacelift_element(client: &crate::http::Client, endpoint: &str, token: &str, stack: &str, name: &str) -> Result<Option<Value>, String> {
    let query = "query($stack: ID!, $id: ID!) { stack(id: $stack) { configElement(id: $id) { id type value writeOnly description } } }";
    let data = spacelift_graphql(client, endpoint, Some(token), query, json!({"stack": stack, "id": name})).await?;
    Ok(data.get("stack").and_then(|s| s.get("configElement")).filter(|v| !v.is_null()).cloned())
}
pub async fn spacelift_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let endpoint = spacelift_endpoint(config)?; let stack = cfg(config, "stack_id");
    if stack.is_empty() { return Err("Spacelift requires stack_id".into()); }
    let mode = sync_mode(config, "spacelift")?; let dry = is_dry(config);
    let write_only = config.get("write_only").and_then(Value::as_bool).unwrap_or(false);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let token = spacelift_auth(&client, &endpoint, config).await?;
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    let mut managed = Vec::new();
    for (name, value) in &desired {
        let existing = spacelift_element(&client, &endpoint, &token, stack, name).await?;
        let same = existing.as_ref().map(|e| e.get("value").and_then(Value::as_str) == Some(value.as_str())).unwrap_or(false);
        if same { unchanged += 1; }
        else {
            if existing.is_some() { if !dry { let query = "mutation($stack: ID!, $id: ID!) { stackConfigDelete(stack: $stack, id: $id) { id } }"; spacelift_graphql(&client, &endpoint, Some(&token), query, json!({"stack": stack, "id": name})).await?; } updated += 1; }
            else { created += 1; }
            if !dry {
                let query = "mutation($stack: ID!, $id: ID!, $value: String!, $writeOnly: Boolean!) { stackConfigAdd(stack: $stack, config: {id: $id, type: ENVIRONMENT_VARIABLE, value: $value, writeOnly: $writeOnly}) { id } }";
                spacelift_graphql(&client, &endpoint, Some(&token), query, json!({"stack": stack, "id": name, "value": value, "writeOnly": write_only})).await.map_err(|e| format!("Spacelift create {} failed: {}", name, e))?;
            }
        }
        managed.push(name.clone());
    }
    let mut deleted = 0;
    if mode == "mirror" {
        for name in previous_managed {
            if desired.iter().any(|(n, _)| n == name) { continue; }
            if spacelift_element(&client, &endpoint, &token, stack, name).await?.is_some() {
                if !dry { let query = "mutation($stack: ID!, $id: ID!) { stackConfigDelete(stack: $stack, id: $id) { id } }"; spacelift_graphql(&client, &endpoint, Some(&token), query, json!({"stack": stack, "id": name})).await?; }
                deleted += 1;
            }
        }
    }
    Ok((format!("Spacelift sync{}: stack={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, stack, created, updated, unchanged, deleted), managed))
}
pub async fn spacelift_test(config: &Value) -> Result<String, String> {
    let endpoint = spacelift_endpoint(config)?; let stack = cfg(config, "stack_id");
    if stack.is_empty() { return Err("Spacelift requires stack_id".into()); }
    let client = http_client(); let token = spacelift_auth(&client, &endpoint, config).await?;
    let data = spacelift_graphql(&client, &endpoint, Some(&token), "query($stack: ID!) { stack(id: $stack) { id } }", json!({"stack": stack})).await?;
    let id = data.get("stack").and_then(|s| s.get("id")).and_then(Value::as_str).unwrap_or(stack);
    Ok(format!("Spacelift connection OK: stack {} is reachable", id))
}

// ---------- Rundeck ----------
fn rundeck_parts(config: &Value) -> Result<(String, String), String> {
    let instance = cfg(config, "instance_url").trim_end_matches('/'); let token = cfg(config, "api_token"); let project = cfg(config, "project");
    if instance.is_empty() || token.is_empty() || project.is_empty() { return Err("Rundeck requires instance_url, api_token and project".into()); }
    let path = cfg(config, "path").trim_matches('/');
    let encoded = if path.is_empty() { String::new() } else { path.split('/').map(enc).collect::<Vec<_>>().join("/") };
    let base = format!("{}/api/19/storage/keys/project/{}", instance, enc(project));
    Ok((if encoded.is_empty() { base } else { format!("{}/{}", base, encoded) }, token.to_string()))
}
async fn rundeck_keys(client: &crate::http::Client, base: &str, token: &str) -> Result<Vec<String>, String> {
    match req(client.get(base).header("X-Rundeck-Auth-Token", token)).await {
        Ok(text) => { let value: Value = serde_json::from_str(&text).map_err(|e| format!("Rundeck invalid key list: {}", e))?;
            Ok(value.get("resources").and_then(Value::as_array).map(|items| items.iter().filter(|r| r.get("type").and_then(Value::as_str) == Some("file")).filter_map(|r| r.get("name").and_then(Value::as_str).map(str::to_string)).collect()).unwrap_or_default()) }
        Err(e) if e.contains("HTTP 404") => Ok(Vec::new()),
        Err(e) => Err(format!("Rundeck list keys failed: {}", e)),
    }
}
pub async fn rundeck_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token) = rundeck_parts(config)?; let mode = sync_mode(config, "rundeck")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let existing = rundeck_keys(&client, &base, &token).await?;
    let (mut created, mut updated) = (0, 0);
    if !dry {
        for (name, value) in &desired {
            let url = format!("{}/{}", base, enc(name));
            if existing.contains(name) { req(client.put(&url).header("X-Rundeck-Auth-Token", &token).header("Content-Type", "application/x-rundeck-data-password").body(value.clone())).await.map_err(|e| format!("Rundeck update {} failed: {}", name, e))?; updated += 1; }
            else { req(client.post(&url).header("X-Rundeck-Auth-Token", &token).header("Content-Type", "application/x-rundeck-data-password").body(value.clone())).await.map_err(|e| format!("Rundeck create {} failed: {}", name, e))?; created += 1; }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !existing.contains(name) { continue; }
            req(client.delete(format!("{}/{}", base, enc(name))).header("X-Rundeck-Auth-Token", &token)).await.map_err(|e| format!("Rundeck delete {} failed: {}", name, e))?; } }
    } else { for (name, _) in &desired { if existing.contains(name) { updated += 1; } else { created += 1; } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && existing.contains(n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Rundeck sync{}: created={} updated={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, deleted), managed))
}
pub async fn rundeck_test(config: &Value) -> Result<String, String> {
    let (base, token) = rundeck_parts(config)?;
    let keys = rundeck_keys(&http_client(), &base, &token).await?;
    Ok(format!("Rundeck connection OK: {} key(s) visible", keys.len()))
}

// ---------- Cloud 66 ----------
fn cloud66_parts(config: &Value) -> Result<(String, String, String), String> {
    let base = base(config, "https://app.cloud66.com/api"); let token = cfg(config, "access_token"); let stack = cfg(config, "stack_id");
    if token.is_empty() || stack.is_empty() { return Err("Cloud 66 requires access_token and stack_id".into()); }
    Ok((base, token.to_string(), stack.to_string()))
}
async fn cloud66_list(client: &crate::http::Client, base: &str, token: &str, stack: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut page = 1i64;
    loop {
        let text = req(client.get(format!("{}/3/stacks/{}/environments?page={}&per_page=100", base, enc(stack), page)).bearer_auth(token)).await.map_err(|e| format!("Cloud 66 list failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Cloud 66 invalid env var list: {}", e))?;
        if let Some(items) = value.get("response").and_then(Value::as_array) { out.extend(items.iter().cloned()); }
        page = value.get("pagination").and_then(|p| p.get("next")).and_then(Value::as_i64).unwrap_or(0);
        if page == 0 { break; }
    }
    Ok(out)
}
fn cloud66_modifiable(value: &Value) -> bool {
    !value.get("readonly").and_then(Value::as_bool).unwrap_or(false) && !value.get("is_generated").and_then(Value::as_bool).unwrap_or(false)
}
pub async fn cloud66_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token, stack) = cloud66_parts(config)?; let mode = sync_mode(config, "cloud66")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let root = format!("{}/3/stacks/{}/environments", base, enc(&stack));
    let remote = cloud66_list(&client, &base, &token, &stack).await?;
    let by_key: HashMap<String, (String, bool)> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), (v.get("value").and_then(Value::as_str).unwrap_or("").to_string(), cloud66_modifiable(v))))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            if name.contains('-') { continue; }
            match by_key.get(name) {
                Some((_, false)) => {}
                Some((old, true)) if old == value => unchanged += 1,
                Some((_, true)) => { req(client.put(format!("{}/{}", root, enc(name))).bearer_auth(&token).json(&json!({"value": value}))).await.map_err(|e| format!("Cloud 66 update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(&root).bearer_auth(&token).json(&json!({"key": name, "value": value}))).await.map_err(|e| format!("Cloud 66 create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.get(name).map(|(_, m)| *m).unwrap_or(false) { continue; }
            req(client.delete(format!("{}/{}", root, enc(name))).bearer_auth(&token)).await.map_err(|e| format!("Cloud 66 delete {} failed: {}", name, e))?; } }
    } else { for (name, value) in &desired { if name.contains('-') { continue; } match by_key.get(name) { Some((old, true)) if old == value => unchanged += 1, Some((_, true)) => updated += 1, Some((_, false)) => {}, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.get(*n).map(|(_, m)| *m).unwrap_or(false)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Cloud 66 sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn cloud66_test(config: &Value) -> Result<String, String> {
    let (base, token, stack) = cloud66_parts(config)?;
    let list = cloud66_list(&http_client(), &base, &token, &stack).await?;
    Ok(format!("Cloud 66 connection OK: {} environment variable(s) visible", list.len()))
}

// ---------- Humanitec ----------
fn humanitec_parts(config: &Value) -> Result<(String, String, String, String, String, String), String> {
    let base = base(config, "https://api.humanitec.io"); let token = cfg(config, "api_token"); let org = cfg(config, "org"); let app = cfg(config, "app");
    let scope = { let s = cfg(config, "scope"); if s.is_empty() { "application" } else { s } };
    if token.is_empty() || org.is_empty() || app.is_empty() { return Err("Humanitec requires api_token, org and app".into()); }
    if scope != "application" && scope != "environment" { return Err("Humanitec scope must be application or environment".into()); }
    let env = cfg(config, "env");
    if scope == "environment" && env.is_empty() { return Err("Humanitec environment scope requires env".into()); }
    Ok((base, token.to_string(), org.to_string(), app.to_string(), scope.to_string(), env.to_string()))
}
fn humanitec_values_url(base: &str, org: &str, app: &str, scope: &str, env: &str) -> String {
    if scope == "environment" { format!("{}/orgs/{}/apps/{}/envs/{}/values", base, enc(org), enc(app), enc(env)) } else { format!("{}/orgs/{}/apps/{}/values", base, enc(org), enc(app)) }
}
async fn humanitec_list(client: &crate::http::Client, config: &Value) -> Result<Vec<Value>, String> {
    let (base, token, org, app, scope, env) = humanitec_parts(config)?;
    let text = req(client.get(humanitec_values_url(&base, &org, &app, &scope, &env)).bearer_auth(&token).header("Accept", "application/json")).await.map_err(|e| format!("Humanitec list failed: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Humanitec invalid values response: {}", e))
}
pub async fn humanitec_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, token, org, app, scope, env) = humanitec_parts(config)?; let mode = sync_mode(config, "humanitec")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let remote = humanitec_list(&client, config).await?;
    let by_key: HashMap<String, (String, String)> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), (v.get("value").and_then(Value::as_str).unwrap_or("").to_string(), v.get("source").and_then(Value::as_str).unwrap_or("app").to_string())))).collect();
    let app_root = format!("{}/orgs/{}/apps/{}/values", base, enc(&org), enc(&app));
    let env_root = format!("{}/orgs/{}/apps/{}/envs/{}/values", base, enc(&org), enc(&app), enc(&env));
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            let existing = by_key.get(name);
            if scope == "environment" {
                if let Some((old, _)) = existing {
                    if old == value { unchanged += 1; continue; }
                    req(client.patch(format!("{}/{}", env_root, enc(name))).bearer_auth(&token).json(&json!({"value": value, "description": ""}))).await.map_err(|e| format!("Humanitec update {} failed: {}", name, e))?; updated += 1;
                } else {
                    req(client.post(&app_root).bearer_auth(&token).json(&json!({"key": name, "value": "", "description": "", "is_secret": true}))).await.map_err(|e| format!("Humanitec create {} failed: {}", name, e))?;
                    req(client.patch(format!("{}/{}", env_root, enc(name))).bearer_auth(&token).json(&json!({"value": value, "description": ""}))).await.map_err(|e| format!("Humanitec set environment value {} failed: {}", name, e))?;
                    created += 1;
                }
            } else if let Some((old, _)) = existing {
                if old == value { unchanged += 1; continue; }
                req(client.patch(format!("{}/{}", app_root, enc(name))).bearer_auth(&token).json(&json!({"value": value, "description": ""}))).await.map_err(|e| format!("Humanitec update {} failed: {}", name, e))?; updated += 1;
            } else {
                req(client.post(&app_root).bearer_auth(&token).json(&json!({"key": name, "value": value, "description": "", "is_secret": true}))).await.map_err(|e| format!("Humanitec create {} failed: {}", name, e))?; created += 1;
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) { continue; }
            let source = by_key.get(name).map(|(_, s)| s.as_str()).unwrap_or("");
            if scope == "environment" && source == "app" { continue; }
            let url = if scope == "environment" { format!("{}/{}", env_root, enc(name)) } else { format!("{}/{}", app_root, enc(name)) };
            if by_key.contains_key(name) { req(client.delete(&url).bearer_auth(&token)).await.map_err(|e| format!("Humanitec delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { match by_key.get(name) { Some((old, _)) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Humanitec sync{}: scope={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, scope, created, updated, unchanged, deleted), managed))
}
pub async fn humanitec_test(config: &Value) -> Result<String, String> {
    let list = humanitec_list(&http_client(), config).await?;
    Ok(format!("Humanitec connection OK: {} value(s) visible", list.len()))
}

// ---------- Scaleway Secret Manager ----------
// One opaque secret per key. Versions are immutable, so a changed value is a new
// version and the previous one is disabled. `data` is base64 on the wire.
fn scaleway_parts(config: &Value) -> Result<(String, String, String, String, String), String> {
    let region = cfg(config, "region"); let token = cfg(config, "secret_key"); let project = cfg(config, "project_id");
    if region.is_empty() || token.is_empty() || project.is_empty() { return Err("Scaleway Secret Manager requires region, secret_key and project_id".into()); }
    if !matches!(region, "fr-par" | "nl-ams" | "pl-waw") { return Err(format!("Scaleway region must be fr-par, nl-ams or pl-waw (got {:?})", region)); }
    Ok((base(config, "https://api.scaleway.com"), region.to_string(), token.to_string(), project.to_string(), cfg(config, "path").trim_matches('/').to_string()))
}
fn scaleway_root(base: &str, region: &str) -> String { format!("{}/secret-manager/v1beta1/regions/{}", base, region) }
async fn scaleway_list(client: &crate::http::Client, root: &str, token: &str, project: &str, path: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut page = 1i64;
    loop {
        let mut url = format!("{}/secrets?project_id={}&scheduled_for_deletion=false&page={}&page_size=100", root, enc(project), page);
        if !path.is_empty() { url.push_str(&format!("&path={}", enc(path))); }
        let text = req(client.get(&url).header("X-Auth-Token", token)).await.map_err(|e| format!("Scaleway list failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Scaleway invalid secret list: {}", e))?;
        let items = value.get("secrets").and_then(Value::as_array).cloned().unwrap_or_default();
        let count = items.len();
        out.extend(items);
        let total = value.get("total_count").and_then(Value::as_i64).unwrap_or(out.len() as i64);
        if count == 0 || out.len() as i64 >= total { break; }
        page += 1;
        if page > 100 { return Err("Scaleway secret list did not terminate".into()); }
    }
    Ok(out)
}
async fn scaleway_latest(client: &crate::http::Client, root: &str, token: &str, id: &str) -> Result<Option<String>, String> {
    match req(client.get(format!("{}/secrets/{}/versions/latest/access", root, enc(id))).header("X-Auth-Token", token)).await {
        Ok(text) => { let value: Value = serde_json::from_str(&text).map_err(|e| format!("Scaleway invalid version: {}", e))?;
            let data = value.get("data").and_then(Value::as_str).unwrap_or("");
            if data.is_empty() { return Ok(None); }
            Ok(Some(String::from_utf8(openwarp_crypto::unb64(data).map_err(|e| format!("Scaleway secret data is not base64: {}", e))?).map_err(|_| "Scaleway secret data is not UTF-8".to_string())?)) }
        Err(e) if e.contains("HTTP 404") => Ok(None),
        Err(e) => Err(format!("Scaleway read version failed: {}", e)),
    }
}
pub async fn scaleway_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base, region, token, project, path) = scaleway_parts(config)?; let mode = sync_mode(config, "scaleway")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client(); let root = scaleway_root(&base, &region);
    let remote = scaleway_list(&client, &root, &token, &project, &path).await?;
    let by_name: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("id")?.as_str()?.to_string()))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            let data = openwarp_crypto::b64(value.as_bytes());
            if let Some(id) = by_name.get(name) {
                match scaleway_latest(&client, &root, &token, id).await? {
                    Some(old) if old == *value => unchanged += 1,
                    _ => { req(client.post(format!("{}/secrets/{}/versions", root, enc(id))).header("X-Auth-Token", &token).json(&json!({"data": data, "disable_previous": true}))).await.map_err(|e| format!("Scaleway version {} failed: {}", name, e))?; updated += 1; }
                }
            } else {
                let text = req(client.post(format!("{}/secrets", root)).header("X-Auth-Token", &token).json(&json!({"name": name, "project_id": project, "type": "opaque", "path": path}))).await.map_err(|e| format!("Scaleway create {} failed: {}", name, e))?;
                let created_secret: Value = serde_json::from_str(&text).map_err(|e| format!("Scaleway invalid create response: {}", e))?;
                let id = created_secret.get("id").and_then(Value::as_str).ok_or_else(|| format!("Scaleway create response for {} has no id", name))?;
                req(client.post(format!("{}/secrets/{}/versions", root, enc(id))).header("X-Auth-Token", &token).json(&json!({"data": data}))).await.map_err(|e| format!("Scaleway version {} failed: {}", name, e))?;
                created += 1;
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) { continue; }
            if let Some(id) = by_name.get(name) { req(client.delete(format!("{}/secrets/{}", root, enc(id))).header("X-Auth-Token", &token)).await.map_err(|e| format!("Scaleway delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { match by_name.get(name) { Some(id) => match scaleway_latest(&client, &root, &token, id).await? { Some(old) if old == *value => unchanged += 1, _ => updated += 1 }, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Scaleway Secret Manager sync{}: region={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, region, created, updated, unchanged, deleted), managed))
}
pub async fn scaleway_test(config: &Value) -> Result<String, String> {
    let (base, region, token, project, path) = scaleway_parts(config)?;
    let list = scaleway_list(&http_client(), &scaleway_root(&base, &region), &token, &project, &path).await?;
    Ok(format!("Scaleway connection OK: {} secret(s) visible in {}", list.len(), region))
}

// ---------- Azure App Configuration ----------
// Key-values addressed by key plus an optional label. Auth is the documented
// HMAC-SHA256 scheme: the access key value is base64, and the signature covers
// method, path+query and the x-ms-date, host and content hash.
fn appconfig_parts(config: &Value) -> Result<(String, String, String, String), String> {
    let endpoint = cfg(config, "endpoint").trim_end_matches('/').to_string();
    let id = cfg(config, "id"); let secret = cfg(config, "secret");
    if endpoint.is_empty() || id.is_empty() || secret.is_empty() { return Err("Azure App Configuration requires endpoint, id and secret".into()); }
    let url = reqwest::Url::parse(&endpoint).map_err(|e| format!("Azure App Configuration endpoint is invalid: {}", e))?;
    if url.scheme() != "https" && url.scheme() != "http" { return Err("Azure App Configuration endpoint must be http(s)".into()); }
    let host = url.host_str().ok_or("Azure App Configuration endpoint has no host")?;
    let host = match url.port() { Some(p) => format!("{}:{}", host, p), None => host.to_string() };
    Ok((format!("{}://{}", url.scheme(), host), host, id.to_string(), secret.to_string()))
}
fn appconfig_label(config: &Value) -> String { cfg(config, "label").to_string() }
fn appconfig_query(label: &str) -> String { if label.is_empty() { "api-version=1.0".into() } else { format!("label={}&api-version=1.0", enc(label)) } }
fn appconfig_sign(method: &str, path_and_query: &str, host: &str, body: &str, id: &str, secret_b64: &str) -> Result<Vec<(String, String)>, String> {
    let key = openwarp_crypto::unb64(secret_b64).map_err(|_| "Azure App Configuration secret must be the base64 access key value".to_string())?;
    let date = http_date();
    let content_hash = openwarp_crypto::b64(&Sha256::digest(body.as_bytes()));
    let to_sign = format!("{}\n{}\n{};{};{}", method.to_ascii_uppercase(), path_and_query, date, host, content_hash);
    let signature = openwarp_crypto::b64(&hmac(&key, to_sign.as_bytes()));
    Ok(vec![
        ("x-ms-date".into(), date),
        ("x-ms-content-sha256".into(), content_hash),
        ("Authorization".into(), format!("HMAC-SHA256 Credential={}&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={}", id, signature)),
    ])
}
fn appconfig_request(client: &crate::http::Client, method: reqwest::Method, url: &str, host: &str, body: &str, id: &str, secret: &str) -> Result<crate::http::RequestBuilder, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let path_and_query = match parsed.query() { Some(q) => format!("{}?{}", parsed.path(), q), None => parsed.path().to_string() };
    let mut request = client.request(method.clone(), url);
    for (name, value) in appconfig_sign(method.as_str(), &path_and_query, host, body, id, secret)? { request = request.header(name.as_str(), value.as_str()); }
    if !body.is_empty() { request = request.header("Content-Type", "application/vnd.microsoft.appconfig.kv+json"); }
    Ok(request.body(body.to_string()))
}
async fn appconfig_list(client: &crate::http::Client, endpoint: &str, host: &str, id: &str, secret: &str, label: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut path = format!("/kv?key=*&label={}&api-version=1.0", if label.is_empty() { "%00".to_string() } else { enc(label) });
    for _ in 0..100 {
        let url = format!("{}{}", endpoint, path);
        let text = req(appconfig_request(client, reqwest::Method::GET, &url, host, "", id, secret)?).await.map_err(|e| format!("Azure App Configuration list failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Azure App Configuration invalid list: {}", e))?;
        if let Some(items) = value.get("items").and_then(Value::as_array) { out.extend(items.iter().cloned()); }
        let next = value.get("@nextLink").and_then(Value::as_str).unwrap_or("");
        if next.is_empty() { break; }
        path = if next.starts_with('/') { next.to_string() } else { reqwest::Url::parse(next).map(|u| match u.query() { Some(q) => format!("{}?{}", u.path(), q), None => u.path().to_string() }).unwrap_or_default() };
        if path.is_empty() { break; }
    }
    Ok(out)
}
pub async fn azure_app_configuration_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (endpoint, host, id, secret) = appconfig_parts(config)?; let mode = sync_mode(config, "azure_app_configuration")?; let dry = is_dry(config);
    let label = appconfig_label(config);
    let desired = trigger_desired(config, secrets);
    let client = http_client();
    let remote = appconfig_list(&client, &endpoint, &host, &id, &secret, &label).await?;
    let by_key: HashMap<String, String> = remote.iter().filter_map(|v| Some((v.get("key")?.as_str()?.to_string(), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            match by_key.get(name) {
                Some(old) if old == value => unchanged += 1,
                other => {
                    let url = format!("{}/kv/{}?{}", endpoint, enc(name), appconfig_query(&label));
                    let body = json!({"value": value}).to_string();
                    req(appconfig_request(&client, reqwest::Method::PUT, &url, &host, &body, &id, &secret)?).await.map_err(|e| format!("Azure App Configuration set {} failed: {}", name, e))?;
                    if other.is_some() { updated += 1; } else { created += 1; }
                }
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !by_key.contains_key(name) { continue; }
            let url = format!("{}/kv/{}?{}", endpoint, enc(name), appconfig_query(&label));
            req(appconfig_request(&client, reqwest::Method::DELETE, &url, &host, "", &id, &secret)?).await.map_err(|e| format!("Azure App Configuration delete {} failed: {}", name, e))?; } }
    } else { for (name, value) in &desired { match by_key.get(name) { Some(old) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_key.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Azure App Configuration sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn azure_app_configuration_test(config: &Value) -> Result<String, String> {
    let (endpoint, host, id, secret) = appconfig_parts(config)?;
    let list = appconfig_list(&http_client(), &endpoint, &host, &id, &secret, &appconfig_label(config)).await?;
    Ok(format!("Azure App Configuration connection OK: {} key-value(s) visible", list.len()))
}

// ---------- OVHcloud KMS ----------
fn ovh_kms_parts(config: &Value) -> Result<(String, String, String), String> {
    let domain = cfg(config, "okms_domain").trim_end_matches('/').to_string();
    let id = cfg(config, "okms_id"); let path = cfg(config, "path").trim_matches('/');
    if domain.is_empty() || id.is_empty() || path.is_empty() { return Err("OVHcloud KMS requires okms_domain, okms_id and path".into()); }
    if cfg(config, "token").is_empty() && (cfg(config, "certificate").is_empty() || cfg(config, "private_key").is_empty()) {
        return Err("OVHcloud KMS requires token, or certificate and private_key".into());
    }
    Ok((domain, id.to_string(), path.to_string()))
}
fn ovh_kms_client(config: &Value) -> Result<crate::http::Client, String> {
    let cert = cfg(config, "certificate"); let key = cfg(config, "private_key");
    if cert.is_empty() && key.is_empty() { return Ok(http_client()); }
    if cert.is_empty() || key.is_empty() { return Err("OVHcloud KMS requires both certificate and private_key".into()); }
    #[cfg(target_arch = "wasm32")]
    { let _ = (cert, key); Err("OVHcloud KMS client certificates are unavailable on Workers".into()) }
    #[cfg(not(target_arch = "wasm32"))]
    {
        reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none())
            .identity(reqwest::Identity::from_pem(format!("{}\n{}", cert, key).as_bytes()).map_err(|e| format!("OVHcloud KMS client certificate is invalid: {}", e))?)
            .build().map_err(|e| e.to_string())
    }
}
fn ovh_auth(request: crate::http::RequestBuilder, config: &Value) -> crate::http::RequestBuilder {
    let token = cfg(config, "token");
    if token.is_empty() { request } else { request.bearer_auth(token) }
}
async fn ovh_kms_bundle(client: &crate::http::Client, config: &Value) -> Result<(bool, HashMap<String, String>, Option<i64>), String> {
    let (domain, id, path) = ovh_kms_parts(config)?;
    let response = ovh_auth(client.get(format!("{}/api/{}/v2/secret/{}?includeData=true", domain, enc(&id), enc(&path))), config).send().await.map_err(|e| format!("OVHcloud KMS read failed: {}", e))?;
    let status = response.status(); let text = response.text().await.unwrap_or_default();
    if status.as_u16() == 404 { return Ok((false, HashMap::new(), None)); }
    if !status.is_success() { return Err(format!("OVHcloud KMS read failed: HTTP {}: {}", status, text.chars().take(400).collect::<String>())); }
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("OVHcloud KMS invalid response: {}", e))?;
    let version = value.get("metadata").and_then(|m| m.get("currentVersion")).and_then(Value::as_i64);
    let data = value.get("version").and_then(|v| v.get("data")).and_then(Value::as_object).map(|object| object.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect()).unwrap_or_default();
    Ok((true, data, version))
}
pub async fn ovh_kms_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (domain, id, path) = ovh_kms_parts(config)?; let mode = sync_mode(config, "ovh_kms")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let client = ovh_kms_client(config)?;
    let (exists, current, version) = ovh_kms_bundle(&client, config).await?;
    let (merged, created, updated, unchanged, deleted) = merge_pairs(&current, &desired, previous_managed, mode == "mirror");
    let data: serde_json::Map<String, Value> = merged.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    if !dry && (created > 0 || updated > 0 || deleted > 0 || !exists) {
        if exists {
            let url = match version { Some(v) => format!("{}/api/{}/v2/secret/{}?cas={}", domain, enc(&id), enc(&path), v), None => format!("{}/api/{}/v2/secret/{}", domain, enc(&id), enc(&path)) };
            req(ovh_auth(client.put(&url), config).json(&json!({"version": {"data": data}}))).await.map_err(|e| format!("OVHcloud KMS update failed: {}", e))?;
        } else {
            req(ovh_auth(client.post(format!("{}/api/{}/v2/secret", domain, enc(&id))), config).json(&json!({"path": path, "version": {"data": data}}))).await.map_err(|e| format!("OVHcloud KMS create failed: {}", e))?;
        }
    }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("OVHcloud KMS sync{}: path={} created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, path, created, updated, unchanged, deleted), managed))
}
pub async fn ovh_kms_test(config: &Value) -> Result<String, String> {
    let (domain, id, _) = ovh_kms_parts(config)?;
    let client = ovh_kms_client(config)?;
    req(ovh_auth(client.get(format!("{}/api/{}/v1/servicekey", domain, enc(&id))), config)).await.map_err(|e| format!("OVHcloud KMS connection failed: {}", e))?;
    Ok(format!("OVHcloud KMS connection OK: domain {} is reachable", domain))
}

// ---------- Keeper Commander ----------
fn keeper_parts(config: &Value) -> Result<(String, String, String), String> {
    let base = cfg(config, "instance_url").trim_end_matches('/').to_string(); let key = cfg(config, "api_key"); let folder = cfg(config, "folder_uid");
    if base.is_empty() || key.is_empty() || folder.is_empty() { return Err("Keeper requires instance_url, api_key and folder_uid".into()); }
    Ok((base, key.to_string(), folder.to_string()))
}
fn quote_keeper_arg(value: &str) -> String { format!("'{}'", value.replace('\'', "'\"'\"'")) }
async fn keeper_execute(config: &Value, command: &str) -> Result<String, String> {
    let (base, key, _) = keeper_parts(config)?;
    let client = http_client();
    let response = client.post(format!("{}/api/v1/executecommand", base)).header("api-key", &key).json(&json!({"command": command})).send().await.map_err(|e| format!("Keeper command failed: {}", e))?;
    let status = response.status(); let text = response.text().await.unwrap_or_default();
    if !status.is_success() { return Err(format!("Keeper command failed: HTTP {}: {}", status, text.chars().take(400).collect::<String>())); }
    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        if value.get("error").and_then(Value::as_str).map(|e| !e.is_empty()).unwrap_or(false) { return Err(format!("Keeper command failed: {}", value["error"])); }
    }
    Ok(text)
}
async fn keeper_records(config: &Value) -> Result<HashMap<String, (String, String)>, String> {
    let (_, _, folder) = keeper_parts(config)?;
    keeper_execute(config, "sync-down").await?;
    let listing = keeper_execute(config, &format!("ls --format=json {}", quote_keeper_arg(&folder))).await?;
    let value: Value = serde_json::from_str(&listing).map_err(|e| format!("Keeper invalid folder listing: {}", e))?;
    let entries = value.as_array().cloned().or_else(|| value.get("records").and_then(Value::as_array).cloned()).unwrap_or_default();
    let mut out = HashMap::new();
    for entry in entries {
        let uid = entry.get("uid").or_else(|| entry.get("record_uid")).and_then(Value::as_str).unwrap_or("");
        if uid.is_empty() || uid.starts_with('-') || !uid.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) { continue; }
        let record_text = keeper_execute(config, &format!("get --format=json {}", uid)).await?;
        let record: Value = serde_json::from_str(&record_text).map_err(|e| format!("Keeper invalid record {}: {}", uid, e))?;
        if record.get("type").and_then(Value::as_str) != Some("login") { continue; }
        let title = record.get("title").and_then(Value::as_str).unwrap_or("").to_string();
        if title.is_empty() { continue; }
        let password = record.get("fields").and_then(Value::as_array).and_then(|fields| fields.iter().find(|f| f.get("type").and_then(Value::as_str) == Some("password"))).and_then(|f| f.get("value")).and_then(Value::as_array).and_then(|values| values.first()).and_then(Value::as_str).unwrap_or("").to_string();
        out.insert(title, (uid.to_string(), password));
    }
    Ok(out)
}
pub async fn keeper_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (_, _, folder) = keeper_parts(config)?; let mode = sync_mode(config, "keeper")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| n.contains("${")) { return Err(format!("Keeper cannot store keys containing ${{: {:?}", name)); }
    let current = keeper_records(config).await?;
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, value) in &desired {
            let encoded = openwarp_crypto::b64(value.as_bytes());
            if let Some((uid, old)) = current.get(name) {
                if old == value { unchanged += 1; continue; }
                keeper_execute(config, &format!("record-update -f --record={} {}", uid, quote_keeper_arg(&format!("password=$BASE64:{}", encoded)))).await.map_err(|e| format!("Keeper update {} failed: {}", name, e))?;
                updated += 1;
            } else {
                keeper_execute(config, &format!("record-add -f --folder={} --record-type=login --title={} {}", folder, quote_keeper_arg(name), quote_keeper_arg(&format!("password=$BASE64:{}", encoded)))).await.map_err(|e| format!("Keeper create {} failed: {}", name, e))?;
                created += 1;
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) { continue; }
            if let Some((uid, _)) = current.get(name) { keeper_execute(config, &format!("rm -f --purge {}", uid)).await.map_err(|e| format!("Keeper delete {} failed: {}", name, e))?; } } }
    } else { for (name, value) in &desired { match current.get(name) { Some((_, old)) if old == value => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && current.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Keeper sync{}: created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn keeper_test(config: &Value) -> Result<String, String> {
    let records = keeper_records(config).await?;
    Ok(format!("Keeper connection OK: {} login record(s) in the shared folder", records.len()))
}

// ---------- OCI Vault ----------
fn unix_now() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
fn http_date() -> String {
    let secs = unix_now(); let days = secs.div_euclid(86400); let rem = secs.rem_euclid(86400);
    let (y, mo, d) = civil(days);
    let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let month_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT", day_names[((days + 4).rem_euclid(7)) as usize], d, month_names[(mo - 1) as usize], y, rem / 3600, (rem % 3600) / 60, rem % 60)
}
#[cfg(not(target_arch = "wasm32"))]
fn iso_after(days: i64) -> String {
    let secs = unix_now() + days * 86400; let d = secs.div_euclid(86400); let rem = secs.rem_euclid(86400); let (y, mo, day) = civil(d);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, day, rem / 3600, (rem % 3600) / 60, rem % 60)
}
#[cfg(not(target_arch = "wasm32"))]
fn oci_endpoint(config: &Value) -> Result<String, String> {
    let endpoint = cfg(config, "endpoint").trim_end_matches('/');
    if !endpoint.is_empty() { return Ok(endpoint.to_string()); }
    let region = cfg(config, "region");
    if region.is_empty() { return Err("OCI Vault requires region or endpoint".into()); }
    Ok(format!("https://vaults.{}.oraclecloud.com", region))
}
#[cfg(not(target_arch = "wasm32"))]
fn oci_key_id(config: &Value) -> Result<String, String> {
    let (tenancy, user, fingerprint) = (cfg(config, "tenancy_ocid"), cfg(config, "user_ocid"), cfg(config, "fingerprint"));
    if tenancy.is_empty() || user.is_empty() || fingerprint.is_empty() { return Err("OCI Vault requires tenancy_ocid, user_ocid and fingerprint".into()); }
    Ok(format!("{}/{}/{}", tenancy, user, fingerprint))
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn oci_sign(config: &Value, canonical: &str) -> Result<String, String> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{Signer, SignatureEncoding};
    let pem = cfg(config, "private_key");
    if pem.is_empty() { return Err("OCI Vault requires private_key".into()); }
    let key = match rsa::RsaPrivateKey::from_pkcs8_pem(pem) { Ok(k) => k, Err(_) => rsa::RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| format!("OCI private key is invalid: {}", e))? };
    let signing_key = SigningKey::<Sha256>::new(key);
    let signature = signing_key.sign(canonical.as_bytes());
    Ok(openwarp_crypto::b64(&signature.to_bytes()))
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
async fn oci_request(client: &crate::http::Client, config: &Value, method: &str, path_query: &str, body: Option<&Value>) -> Result<Value, String> {
    let base = oci_endpoint(config)?; let url = format!("{}{}", base, path_query);
    let parsed = reqwest::Url::parse(&url).map_err(|e| format!("OCI endpoint is invalid: {}", e))?;
    let host = match parsed.port() { Some(port) => format!("{}:{}", parsed.host_str().unwrap_or(""), port), None => parsed.host_str().unwrap_or("").to_string() };
    let date = http_date(); let body_text = body.map(|v| v.to_string());
    let content_sha = body_text.as_ref().map(|b| openwarp_crypto::b64(&Sha256::digest(b.as_bytes())));
    let (canonical, signed_headers) = if let (Some(text), Some(sha)) = (&body_text, &content_sha) {
        (format!("date: {}\n(request-target): {} {}\nhost: {}\ncontent-length: {}\ncontent-type: application/json\nx-content-sha256: {}", date, method.to_lowercase(), path_query, host, text.len(), sha), "date (request-target) host content-length content-type x-content-sha256")
    } else {
        (format!("date: {}\n(request-target): {} {}\nhost: {}", date, method.to_lowercase(), path_query, host), "date (request-target) host")
    };
    let signature = oci_sign(config, &canonical)?;
    let auth = format!("Signature version=\"1\",keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"", oci_key_id(config)?, signed_headers, signature);
    let mut request = client.request(reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?, &url)
        .header("date", &date).header("host", &host).header("authorization", auth);
    if let (Some(text), Some(sha)) = (&body_text, &content_sha) { request = request.header("content-type", "application/json").header("x-content-sha256", sha).header("content-length", text.len()).body(text.clone()); }
    let response = request.send().await.map_err(|e| format!("OCI Vault request failed: {}", e))?;
    let status = response.status(); let text = response.text().await.unwrap_or_default();
    if !status.is_success() { return Err(format!("OCI Vault request failed: HTTP {}: {}", status, text.chars().take(400).collect::<String>())); }
    if text.trim().is_empty() { Ok(json!({})) } else { serde_json::from_str(&text).map_err(|e| format!("OCI Vault invalid response: {}", e)) }
}
#[cfg(not(target_arch = "wasm32"))]
fn oci_config_ready(config: &Value) -> Result<(String, String), String> {
    let compartment = cfg(config, "compartment_id"); let vault = cfg(config, "vault_id");
    if compartment.is_empty() || vault.is_empty() { return Err("OCI Vault requires compartment_id and vault_id".into()); }
    Ok((compartment.to_string(), vault.to_string()))
}
#[cfg(not(target_arch = "wasm32"))]
fn oci_name_ok(name: &str) -> bool { !name.is_empty() && name.len() <= 256 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) }
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
async fn oci_list(client: &crate::http::Client, config: &Value) -> Result<Vec<Value>, String> {
    let (compartment, vault) = oci_config_ready(config)?;
    let value = oci_request(client, config, "GET", &format!("/20180608/secrets?compartmentId={}&vaultId={}&lifecycleState=ACTIVE&limit=1000", enc(&compartment), enc(&vault)), None).await?;
    Ok(value.get("items").and_then(Value::as_array).cloned().unwrap_or_default())
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
async fn oci_bundle(client: &crate::http::Client, config: &Value, id: &str) -> Result<String, String> {
    let value = oci_request(client, config, "GET", &format!("/20180608/secretBundles/{}", enc(id)), None).await?;
    let content = value.get("secretBundleContent").and_then(|c| c.get("content")).and_then(Value::as_str).unwrap_or("");
    let bytes = openwarp_crypto::unb64(content).map_err(|e| format!("OCI secret content is invalid: {}", e))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
#[cfg(not(target_arch = "wasm32"))]
fn oci_content(value: &str) -> Value { json!({"content": openwarp_crypto::b64(value.as_bytes()), "contentType": "BASE64"}) }
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn oci_vault_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (compartment, vault) = oci_config_ready(config)?; let key_id = cfg(config, "key_id");
    let mode = sync_mode(config, "oci_vault")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| !oci_name_ok(n)) { return Err(format!("OCI secret names must be 1-256 letters, digits, dot, underscore or dash: {:?}", name)); }
    let client = http_client(); let remote = oci_list(&client, config).await?;
    let by_name: HashMap<String, (String, String)> = remote.iter().filter_map(|v| Some((v.get("secretName")?.as_str()?.to_string(), (v.get("id")?.as_str()?.to_string(), v.get("lifecycleState").and_then(Value::as_str).unwrap_or("ACTIVE").to_string())))).collect();
    let (mut created, mut updated) = (0, 0);
    if !dry {
        for (name, value) in &desired {
            if let Some((id, state)) = by_name.get(name) {
                if state == "PENDING_DELETION" { oci_request(&client, config, "POST", &format!("/20180608/secrets/{}/actions/cancelDeletion", enc(id)), Some(&json!({}))).await.map_err(|e| format!("OCI cancel deletion {} failed: {}", name, e))?; }
                oci_request(&client, config, "PUT", &format!("/20180608/secrets/{}", enc(id)), Some(&json!({"secretContent": oci_content(value), "enableAutoGeneration": false}))).await.map_err(|e| format!("OCI update {} failed: {}", name, e))?;
                updated += 1;
            } else {
                if key_id.is_empty() { return Err("OCI Vault requires key_id to create secrets".into()); }
                let body = json!({"compartmentId": compartment, "vaultId": vault, "keyId": key_id, "secretName": name, "enableAutoGeneration": false, "secretContent": oci_content(value)});
                oci_request(&client, config, "POST", "/20180608/secrets", Some(&body)).await.map_err(|e| format!("OCI create {} failed: {}", name, e))?;
                created += 1;
            }
        }
        if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) { continue; }
            if let Some((id, _)) = by_name.get(name) { oci_request(&client, config, "POST", &format!("/20180608/secrets/{}/actions/scheduleDeletion", enc(id)), Some(&json!({"timeOfDeletion": iso_after(7)}))).await.map_err(|e| format!("OCI schedule deletion {} failed: {}", name, e))?; } } }
    } else { for (name, _) in &desired { if by_name.contains_key(name) { updated += 1; } else { created += 1; } } }
    let deleted = previous_managed.iter().filter(|n| !desired.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("OCI Vault sync{}: created={} updated={} deleted={} (deletions are scheduled 7 days out)", if dry { " (dry-run)" } else { "" }, created, updated, deleted), managed))
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn oci_vault_test(config: &Value) -> Result<String, String> {
    let list = oci_list(&http_client(), config).await?;
    Ok(format!("OCI Vault connection OK: {} active secret(s) visible", list.len()))
}

// ---------- Hugging Face Spaces ----------
fn huggingface_space(config: &Value) -> Result<(String, String, String), String> {
    let token = cfg(config, "token"); let namespace = cfg(config, "namespace"); let repo = cfg(config, "repo");
    if token.is_empty() || namespace.is_empty() || repo.is_empty() { return Err("Hugging Face requires token, namespace and repo".into()); }
    let kind = { let k = cfg(config, "target"); if k.is_empty() { "secrets" } else { k } };
    if !matches!(kind, "secrets" | "variables") { return Err("Hugging Face target must be secrets or variables".into()); }
    Ok((base(config, "https://huggingface.co"), token.to_string(), format!("/api/spaces/{}/{}/{}", enc(namespace), enc(repo), kind)))
}
fn huggingface_key_ok(name: &str) -> bool { !name.is_empty() && name.len() <= 128 && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') }
async fn huggingface_space_list(client: &crate::http::Client, base_url: &str, token: &str, path: &str) -> Result<HashMap<String, Option<String>>, String> {
    let text = req(client.get(format!("{}{}", base_url, path)).bearer_auth(token)).await.map_err(|e| format!("Hugging Face list failed: {}", e))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("Hugging Face invalid list response: {}", e))?;
    let object = value.as_object().ok_or("Hugging Face list response is not an object")?;
    Ok(object.iter().map(|(k, v)| (k.clone(), v.get("value").and_then(Value::as_str).map(str::to_string))).collect())
}
pub async fn huggingface_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let (base_url, token, path) = huggingface_space(config)?; let mode = sync_mode(config, "huggingface")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    if let Some((name, _)) = desired.iter().find(|(n, _)| !huggingface_key_ok(n)) { return Err(format!("Hugging Face names must match [A-Za-z][_A-Za-z0-9]*: {:?}", name)); }
    let client = http_client(); let remote = huggingface_space_list(&client, &base_url, &token, &path).await?;
    let readable = path.ends_with("/variables");
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    for (name, value) in &desired {
        match remote.get(name) {
            Some(Some(current)) if current == value => unchanged += 1,
            Some(_) => updated += 1,
            None => created += 1,
        }
        if dry { continue; }
        req(client.post(format!("{}{}", base_url, path)).bearer_auth(&token).json(&json!({"key": name, "value": value}))).await.map_err(|e| format!("Hugging Face set {} failed: {}", name, e))?;
    }
    let mut deleted = 0;
    if mode == "mirror" { for name in previous_managed { if desired.iter().any(|(n, _)| n == name) || !remote.contains_key(name) { continue; }
        deleted += 1;
        if !dry { req(client.delete(format!("{}{}", base_url, path)).bearer_auth(&token).json(&json!({"key": name}))).await.map_err(|e| format!("Hugging Face delete {} failed: {}", name, e))?; } } }
    let managed = desired.iter().map(|(n, _)| n.clone()).collect();
    let note = if readable { "" } else { " (secret values are write-only, so existing names are overwritten)" };
    Ok((format!("Hugging Face sync{}: {} created={} updated={} unchanged={} deleted={}{}", if dry { " (dry-run)" } else { "" }, path.rsplit('/').next().unwrap_or(&path), created, updated, unchanged, deleted, note), managed))
}
pub async fn huggingface_test(config: &Value) -> Result<String, String> {
    let (base_url, token, path) = huggingface_space(config)?;
    let list = huggingface_space_list(&http_client(), &base_url, &token, &path).await?;
    Ok(format!("Hugging Face connection OK: {} {} visible", list.len(), path.rsplit('/').next().unwrap_or("entries")))
}

// ---------- SSH file sync ----------
// Writes selected secret folders to files on a host over SSH. This is a remote
// env file, not an account SSH-key store: the host never learns a shell.
#[cfg(not(target_arch = "wasm32"))]
fn ssh_shell_quote(value: &str) -> String { format!("'{}'", value.replace('\'', "'\\''")) }
#[cfg(not(target_arch = "wasm32"))]
struct SshTarget { host: String, port: u16, user: String, identity: String, known_hosts: String, password: String, askpass: String, timeout: u64 }
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn ssh_target(config: &Value) -> Result<SshTarget, String> {
    let host = cfg(config, "host").trim();
    if host.is_empty() || host.contains([' ', '\n', '\t']) { return Err("ssh requires host".into()); }
    let port = config_i64(config, "port").unwrap_or(22);
    if !(1..=65535).contains(&port) { return Err("ssh port must be 1-65535".into()); }
    let user = { let u = cfg(config, "user").trim(); if u.is_empty() { "root" } else { u } };
    if user.contains([' ', '\n', '\t']) { return Err("ssh user must be a single token".into()); }
    let identity = cfg(config, "identity_file").trim().to_string();
    let private_key = cfg(config, "private_key").trim().to_string();
    let password = cfg(config, "password").to_string();
    if identity.is_empty() && private_key.is_empty() && password.is_empty() { return Err("ssh requires identity_file, private_key or password".into()); }
    if !identity.is_empty() && identity.contains('\n') { return Err("ssh identity_file must be a path".into()); }
    let known_hosts = cfg(config, "known_hosts").trim().to_string();
    if known_hosts.is_empty() { return Err("ssh requires known_hosts (the host's public key, or a path to a known_hosts file) so the host is verified".into()); }
    let timeout = config_i64(config, "timeout_secs").unwrap_or(20).clamp(1, 120) as u64;
    Ok(SshTarget { host: host.to_string(), port: port as u16, user: user.to_string(), identity, known_hosts, password, askpass: private_key, timeout })
}
#[cfg(not(target_arch = "wasm32"))]
struct SshFile { path: String, format: String, folders: Vec<String>, owner: String, mode: String }
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn ssh_files(config: &Value) -> Result<Vec<SshFile>, String> {
    let mut out = Vec::new();
    if let Some(items) = config.get("files").and_then(Value::as_array) {
        for item in items {
            let path = item.get("path").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let format = ssh_format(item.get("format").and_then(Value::as_str).unwrap_or(""));
            let folders = item.get("folders").or_else(|| item.get("paths")).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            let owner = item.get("owner").and_then(Value::as_str).unwrap_or("").to_string();
            let mode = item.get("file_mode").and_then(Value::as_str).unwrap_or("").to_string();
            out.push(SshFile { path, format, folders, owner, mode });
        }
    }
    if out.is_empty() {
        let path = cfg(config, "path").trim().to_string();
        let format = ssh_format(cfg(config, "format"));
        out.push(SshFile { path, format, folders: Vec::new(), owner: cfg(config, "owner").to_string(), mode: cfg(config, "file_mode").to_string() });
    }
    for file in &out {
        if !ssh_remote_path_ok(&file.path) { return Err(format!("ssh file path must be absolute and contain no whitespace or quotes: {:?}", file.path)); }
        if !matches!(file.format.as_str(), "dotenv" | "json" | "yaml" | "csv" | "export") { return Err(format!("ssh format must be dotenv (or env), json, yaml, csv or export (got {:?})", file.format)); }
        if !file.owner.is_empty() && !file.owner.bytes().all(|b| b.is_ascii_alphanumeric() || b":_-".contains(&b)) { return Err(format!("ssh owner must be user or user:group: {:?}", file.owner)); }
        if !file.mode.is_empty() && (file.mode.len() > 4 || !file.mode.bytes().all(|b| (b'0'..=b'7').contains(&b))) { return Err(format!("ssh mode must be octal, for example 600: {:?}", file.mode)); }
    }
    let mut seen = std::collections::HashSet::new();
    if let Some(dup) = out.iter().find(|f| !seen.insert(f.path.clone())) { return Err(format!("ssh files must have distinct paths: {:?}", dup.path)); }
    Ok(out)
}
#[cfg(not(target_arch = "wasm32"))]
fn ssh_remote_path_ok(path: &str) -> bool { path.starts_with('/') && path.len() <= 512 && !path.contains('\0') && path.bytes().all(|b| !b.is_ascii_whitespace() && b != b'\'' && b != b'"' && b != b'`' && b != b'\\' && b != b'$') }
#[cfg(not(target_arch = "wasm32"))]
fn ssh_folder_matches(folders: &[String], path: &str) -> bool {
    if folders.is_empty() { return true; }
    let path = if path.is_empty() { "/" } else { path };
    folders.iter().any(|f| { let f = if f.is_empty() { "/" } else { f.as_str() }; path == f || path.starts_with(&format!("{}/", f.trim_end_matches('/'))) })
}
/// `.env` and `env` are the dotenv format under the name the file usually has.
#[cfg(not(target_arch = "wasm32"))]
fn ssh_format(raw: &str) -> String { match raw.trim() { "" | "dotenv" | "env" | ".env" => "dotenv".to_string(), other => other.to_string() } }
#[cfg(not(target_arch = "wasm32"))]
fn ssh_synced_at() -> String { chrono_now() }
#[cfg(not(target_arch = "wasm32"))]
fn ssh_csv_cell(value: &str) -> String { if value.contains([',', '"', '\n', '\r']) { format!("\"{}\"", value.replace('"', "\"\"")) } else { value.to_string() } }
#[cfg(not(target_arch = "wasm32"))]
fn ssh_render(format: &str, pairs: &BTreeMap<String, String>, comment: &str) -> String {
    let note = if comment.is_empty() { String::new() } else { format!("# Synced by OpenWarp at {}\n", comment) };
    match format {
        "json" => { let mut m = serde_json::Map::new(); for (k, v) in pairs { m.insert(k.clone(), json!(v)); } Value::Object(m).to_string() + "\n" }
        "yaml" => { let mut out = note; for (k, v) in pairs { out.push_str(k); out.push_str(": "); out.push_str(&dotenv_quote(v)); out.push('\n'); } out }
        "csv" => { let mut out = String::from("key,value\n"); for (k, v) in pairs { out.push_str(&ssh_csv_cell(k)); out.push(','); out.push_str(&ssh_csv_cell(v)); out.push('\n'); } out }
        "export" => { let mut out = note; for (k, v) in pairs { out.push_str("export "); out.push_str(k); out.push('='); out.push_str(&dotenv_quote(v)); out.push('\n'); } out }
        _ => { let mut out = note; out.push_str(&dotenv_render(pairs)); out }
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn ssh_csv_row(line: &str) -> Option<(String, String)> {
    let mut cells = Vec::new(); let mut cur = String::new(); let mut quoted = false; let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => { cur.push('"'); chars.next(); }
            '"' => quoted = !quoted,
            ',' if !quoted => { cells.push(std::mem::take(&mut cur)); }
            _ => cur.push(c),
        }
    }
    cells.push(cur);
    if cells.len() < 2 { None } else { Some((cells[0].trim().to_string(), cells[1].to_string())) }
}
#[cfg(not(target_arch = "wasm32"))]
fn ssh_parse(format: &str, text: &str) -> Result<BTreeMap<String, String>, String> {
    match format {
        "json" => { if text.trim().is_empty() { return Ok(BTreeMap::new()); } let value: Value = serde_json::from_str(text).map_err(|e| format!("remote file is not JSON: {}", e))?; let object = value.as_object().ok_or("remote file is not a JSON object")?; Ok(object.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect()) }
        "csv" => Ok(text.lines().skip(1).filter_map(ssh_csv_row).filter(|(k, _)| !k.is_empty()).collect()),
        _ => Ok(dotenv_map(text).into_iter().collect()),
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn ssh_binary() -> String { std::env::var("OPENWARP_SSH_BIN").unwrap_or_else(|_| "ssh".to_string()) }
#[cfg(not(target_arch = "wasm32"))]
fn ssh_cleanup(key: &Option<std::path::PathBuf>, hosts: &Option<std::path::PathBuf>) { for path in [key, hosts].into_iter().flatten() { let _ = std::fs::remove_file(path); } }
#[cfg(not(target_arch = "wasm32"))]
fn ssh_stage_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("openwarp-ssh-{}-{:?}", std::process::id(), std::thread::current().id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}
// hash_token is base64, and a slash in a filename silently becomes a directory.
#[cfg(not(target_arch = "wasm32"))]
fn ssh_stage_name(prefix: &str, value: &str) -> String {
    format!("{}-{}", prefix, openwarp_crypto::hash_token(value).replace(['/', '+'], "-").chars().take(12).collect::<String>()) }
#[cfg(not(target_arch = "wasm32"))]
fn wait_bounded(child: std::process::Child, budget: std::time::Duration) -> std::io::Result<std::process::Output> {
    let started = std::time::Instant::now();
    let mut child = child;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new(); let mut stderr = Vec::new();
            use std::io::Read;
            if let Some(mut out) = child.stdout.take() { let _ = out.read_to_end(&mut stdout); }
            if let Some(mut err) = child.stderr.take() { let _ = err.read_to_end(&mut stderr); }
            return Ok(std::process::Output { status, stdout, stderr });
        }
        if started.elapsed() > budget { let _ = child.kill(); let _ = child.wait(); return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("ssh produced no result within {}s; the host may be unreachable or the command stalled", budget.as_secs()))); }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
/// Run one remote command. stdout is the file; a non-zero exit is an error
/// carrying stderr, so a refused host key never looks like an empty file.
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn ssh_exec(target: &SshTarget, command: &str, stdin: Option<&[u8]>) -> Result<String, String> {
    let mut cmd = std::process::Command::new(ssh_binary());
    cmd.arg("-p").arg(target.port.to_string()).arg("-o").arg(format!("ConnectTimeout={}", target.timeout)).arg("-o").arg("StrictHostKeyChecking=yes").arg("-o").arg("IdentitiesOnly=yes");
    // Password auth speaks through sshpass; a key cannot, so BatchMode would reject it.
    if target.password.is_empty() { cmd.arg("-o").arg("BatchMode=yes"); }
    let mut owned_key = None;
    let mut owned_hosts = None;
    if !target.identity.is_empty() { cmd.arg("-i").arg(&target.identity).arg("-o").arg("IdentitiesOnly=yes"); }
    if !target.askpass.is_empty() {
        let path = ssh_stage_dir().join(ssh_stage_name(&format!("key-{}", std::process::id()), &target.askpass));
        let mut pem = target.askpass.clone(); if !pem.ends_with('\n') { pem.push('\n'); }
        std::fs::write(&path, pem.as_bytes()).map_err(|e| format!("ssh could not stage the private key: {}", e))?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)); }
        cmd.arg("-i").arg(&path);
        owned_key = Some(path);
    }
    // A path is only a path when it has no key material. A key always contains whitespace.
    if target.known_hosts.starts_with('/') && !target.known_hosts.contains(' ') { cmd.arg("-o").arg(format!("UserKnownHostsFile={}", target.known_hosts)); }
    else {
        let path = ssh_stage_dir().join(ssh_stage_name("hosts", &target.known_hosts));
        let line = if target.known_hosts.contains(' ') { target.known_hosts.clone() } else { format!("{} {}", target.host, target.known_hosts) };
        std::fs::write(&path, format!("{}\n", line.trim())).map_err(|e| format!("ssh could not stage known_hosts: {}", e))?;
        cmd.arg("-o").arg(format!("UserKnownHostsFile={}", path.display()));
        owned_hosts = Some(path);
    }
    let mut launch: std::process::Command = if target.password.is_empty() { cmd }
    else {
        if std::process::Command::new("sshpass").arg("-V").output().is_err() {
            ssh_cleanup(&owned_key, &owned_hosts);
            return Err("ssh password auth needs sshpass installed, or use identity_file / private_key".into());
        }
        let mut wrapped = std::process::Command::new("sshpass");
        wrapped.arg("-e").arg(ssh_binary());
        wrapped.args(cmd.get_args());
        for (key, value) in cmd.get_envs() { match value { Some(v) => { wrapped.env(key, v); } None => { wrapped.env_remove(key); } } }
        wrapped.env("SSHPASS", &target.password);
        wrapped
    };
    launch.arg(format!("{}@{}", target.user, target.host)).arg("--").arg(command);
    launch.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let spawned = launch.spawn().map_err(|e| format!("ssh could not be started (is OpenSSH installed?): {}", e));
    let mut child = match spawned { Ok(child) => child, Err(e) => { ssh_cleanup(&owned_key, &owned_hosts); return Err(e); } };
    let sent = if let Some(bytes) = stdin { use std::io::Write; child.stdin.take().map(|mut input| input.write_all(bytes)).transpose().map_err(|e| format!("ssh could not send the file: {}", e)) } else { Ok(None) };
    let budget = std::time::Duration::from_secs(target.timeout.saturating_mul(4).max(target.timeout));
    let finished = if sent.is_ok() { Some(wait_bounded(child, budget)) } else { let _ = child.kill(); let _ = child.wait(); None };
    ssh_cleanup(&owned_key, &owned_hosts);
    sent?;
    let finished = finished.unwrap().map_err(|e| format!("ssh wait failed: {}", e))?;
    if !finished.status.success() { return Err(format!("ssh command failed ({}): {}", finished.status, String::from_utf8_lossy(&finished.stderr).chars().take(400).collect::<String>())); }
    Ok(String::from_utf8_lossy(&finished.stdout).into_owned())
}
#[cfg(not(target_arch = "wasm32"))]
type SshPlan = Vec<(SshFile, BTreeMap<String, String>)>;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn ssh_plan(config: &Value, secrets: &[(String, String, String, String)]) -> Result<SshPlan, String> {
    let files = ssh_files(config)?;
    let include: Vec<String> = config.get("include_keys").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let exclude: Vec<String> = config.get("exclude_keys").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let mut claimed: HashMap<String, String> = HashMap::new();
    let mut plans = Vec::new();
    for file in files {
        let mut pairs = BTreeMap::new();
        for (path, key, value, _) in secrets {
            if (!include.is_empty() && !include.contains(key)) || exclude.contains(key) { continue; }
            if !ssh_folder_matches(&file.folders, path) { continue; }
            let name = desired_name(config, key);
            if let Some(earlier) = claimed.insert(name.clone(), file.path.clone()) { return Err(format!("ssh name {:?} is claimed by both {} and {}; a key can feed one file", name, earlier, file.path)); }
            pairs.insert(name, value.clone());
        }
        plans.push((file, pairs));
    }
    Ok(plans)
}
/// Remote names this sync would own, stamped with the file so a failed run can
/// still be pruned later. Empty when the config itself is invalid.
#[cfg(not(target_arch = "wasm32"))]
pub fn ssh_owned_names(config: &Value, secrets: &[(String, String, String, String)]) -> Result<Vec<String>, String> {
    let plans = ssh_plan(config, secrets)?;
    let mut out = Vec::new();
    for (file, pairs) in &plans { for name in pairs.keys() { out.push(format!("{}|{}", file.path, name)); } }
    Ok(out)
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn ssh_file_sync(config: &Value, secrets: &[(String, String, String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let config = config.clone(); let secrets = secrets.to_vec(); let previous_managed = previous_managed.to_vec();
    tokio::task::spawn_blocking(move || ssh_file_sync_blocking(&config, &secrets, &previous_managed)).await.map_err(|e| format!("ssh sync task failed: {}", e))?
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn ssh_file_sync_blocking(config: &Value, secrets: &[(String, String, String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let target = ssh_target(config)?; let mode = sync_mode(config, "ssh")?; let dry = is_dry(config);
    let plans = ssh_plan(config, secrets)?;
    let mut managed = Vec::new(); let mut reports = Vec::new();
    for (file, desired) in &plans {
        let quoted = ssh_shell_quote(&file.path);
        let probe = ssh_exec(&target, &format!("if [ -e {} ]; then echo present; else echo missing; fi", quoted), None)?;
        let missing = probe.trim() == "missing";
        let current_text = if missing { String::new() } else { ssh_exec(&target, &format!("cat {}", quoted), None)? };
        let current = if missing { BTreeMap::new() } else { ssh_parse(&file.format, &current_text)? };
        let current_map: HashMap<String, String> = current.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let desired_pairs: Vec<(String, String)> = desired.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        // A name belongs to the file that last wrote it, so mirror must not strip
        // it from a different file that happens to contain the same text.
        let stamp = format!("{}|", file.path);
        let owned: Vec<String> = previous_managed.iter().filter_map(|n| n.strip_prefix(&stamp).map(str::to_string)).collect();
        let (merged, created, updated, unchanged, deleted) = merge_pairs(&current_map, &desired_pairs, &owned, mode == "mirror");
        if !dry && (created + updated + deleted > 0 || missing) {
            // JSON and CSV have no comment syntax, so a stamp would corrupt them.
            let comment = if matches!(file.format.as_str(), "json" | "csv") || config.get("comment").and_then(Value::as_bool) == Some(false) { String::new() } else { ssh_synced_at() };
            let rendered = ssh_render(&file.format, &merged, &comment);
            // Write beside the target and rename, so a dropped connection cannot
            // leave the previous file emptied by a truncate.
            let staged = format!("{}.openwarp-{}", file.path, std::process::id());
            let dir = file.path.rsplit_once('/').map(|(d, _)| if d.is_empty() { "/" } else { d }).unwrap_or("/");
            let mut command = format!("mkdir -p {} && cat > {} && mv {} {} || {{ rm -f {}; exit 1; }}", ssh_shell_quote(dir), ssh_shell_quote(&staged), ssh_shell_quote(&staged), quoted, ssh_shell_quote(&staged));
            if !file.mode.is_empty() { command.push_str(&format!(" && chmod {} {}", file.mode, quoted)); }
            if !file.owner.is_empty() { command.push_str(&format!(" && chown {} {}", file.owner, quoted)); }
            ssh_exec(&target, &command, Some(rendered.as_bytes()))?;
        }
        if !dry { for name in desired.keys() { managed.push(format!("{}|{}", file.path, name)); } }
        reports.push(format!("{}: created={} updated={} unchanged={} deleted={}", file.path, created, updated, unchanged, deleted));
    }
    Ok((format!("SSH sync{}: {}", if dry { " (dry-run)" } else { "" }, reports.join("; ")), managed))
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn ssh_file_test(config: &Value) -> Result<String, String> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || { let target = ssh_target(&config)?; let who = ssh_exec(&target, "whoami", None)?; Ok(format!("SSH connection OK: {}@{}:{} as {}", target.user, target.host, target.port, who.trim())) }).await.map_err(|e| format!("ssh test task failed: {}", e))?
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn ssh_file_pull(config: &Value) -> Result<Vec<(String, String)>, String> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || ssh_file_pull_blocking(&config)).await.map_err(|e| format!("ssh import task failed: {}", e))?
}
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
fn ssh_file_pull_blocking(config: &Value) -> Result<Vec<(String, String)>, String> {
    let target = ssh_target(config)?; let files = ssh_files(config)?;
    let mut out = Vec::new();
    for file in &files {
        let text = ssh_exec(&target, &format!("cat {}", ssh_shell_quote(&file.path)), None)?;
        for (k, v) in ssh_parse(&file.format, &text)? { out.push((strip_remote_prefix(config, &k, ""), v)); }
    }
    Ok(out)
}

// ---------- Account SSH keys ----------
// Vultr and Hetzner have no updatable secret store. Both keep account SSH keys,
// which is the one object a sync can maintain. A secret value must be a single
// line public key; the secret name becomes the key name.
fn ssh_public_key(name: &str, value: &str) -> Result<String, String> {
    let key = value.trim();
    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 2 || !matches!(parts[0], "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" | "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com") {
        return Err(format!("{:?} is not an OpenSSH public key (expected a single-line ssh-ed25519 or ssh-rsa key)", name));
    }
    Ok(key.to_string())
}
fn vultr_token(config: &Value) -> Result<String, String> {
    let token = cfg(config, "api_key");
    if token.is_empty() { return Err("Vultr requires api_key".into()); }
    Ok(token.to_string())
}
async fn vultr_keys(client: &crate::http::Client, base: &str, token: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut cursor = String::new();
    for _ in 0..100 {
        let url = format!("{}/ssh-keys?per_page=100{}", base, if cursor.is_empty() { String::new() } else { format!("&cursor={}", enc(&cursor)) });
        let text = req(client.get(&url).bearer_auth(token)).await.map_err(|e| format!("Vultr list SSH keys failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Vultr invalid SSH key list: {}", e))?;
        if let Some(items) = value.get("ssh_keys").and_then(Value::as_array) { out.extend(items.iter().cloned()); }
        cursor = value.get("meta").and_then(|m| m.get("links")).and_then(|l| l.get("next")).and_then(Value::as_str).unwrap_or("").to_string();
        if cursor.is_empty() { break; }
    }
    Ok(out)
}
pub async fn vultr_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let token = vultr_token(config)?; let mode = sync_mode(config, "vultr")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let keys: Vec<(String, String)> = desired.iter().map(|(n, v)| ssh_public_key(n, v).map(|k| (n.clone(), k))).collect::<Result<_, _>>()?;
    let client = http_client(); let root = format!("{}/ssh-keys", base(config, "https://api.vultr.com/v2"));
    let remote = vultr_keys(&client, &base(config, "https://api.vultr.com/v2"), &token).await?;
    let by_name: HashMap<String, (String, String)> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), (v.get("id")?.as_str()?.to_string(), v.get("ssh_key").and_then(Value::as_str).unwrap_or("").trim().to_string())))).collect();
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, key) in &keys {
            match by_name.get(name) {
                Some((_, current)) if current == key => unchanged += 1,
                Some((id, _)) => { req(client.patch(format!("{}/{}", root, enc(id))).bearer_auth(&token).json(&json!({"ssh_key": key}))).await.map_err(|e| format!("Vultr update {} failed: {}", name, e))?; updated += 1; }
                None => { req(client.post(&root).bearer_auth(&token).json(&json!({"name": name, "ssh_key": key}))).await.map_err(|e| format!("Vultr create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if keys.iter().any(|(n, _)| n == name) { continue; }
            if let Some((id, _)) = by_name.get(name) { req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Vultr delete {} failed: {}", name, e))?; } } }
    } else { for (name, key) in &keys { match by_name.get(name) { Some((_, current)) if current == key => unchanged += 1, Some(_) => updated += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !keys.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = keys.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Vultr sync{}: ssh keys created={} updated={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, updated, unchanged, deleted), managed))
}
pub async fn vultr_test(config: &Value) -> Result<String, String> {
    let token = vultr_token(config)?;
    let list = vultr_keys(&http_client(), &base(config, "https://api.vultr.com/v2"), &token).await?;
    Ok(format!("Vultr connection OK: {} SSH key(s) visible", list.len()))
}
fn hetzner_token(config: &Value) -> Result<String, String> {
    let token = cfg(config, "token");
    if token.is_empty() { return Err("Hetzner requires token".into()); }
    Ok(token.to_string())
}
fn hetzner_id(value: &Value) -> Option<String> { value.get("id").and_then(|v| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(str::to_string))).filter(|s| !s.is_empty()) }
async fn hetzner_keys(client: &crate::http::Client, base: &str, token: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new(); let mut page = 1i64;
    loop {
        let text = req(client.get(format!("{}/ssh_keys?page={}&per_page=50", base, page)).bearer_auth(token)).await.map_err(|e| format!("Hetzner list SSH keys failed: {}", e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("Hetzner invalid SSH key list: {}", e))?;
        let items = value.get("ssh_keys").and_then(Value::as_array).cloned().unwrap_or_default();
        let count = items.len();
        out.extend(items);
        let next = value.get("meta").and_then(|m| m.get("pagination")).and_then(|p| p.get("next_page")).and_then(Value::as_i64).unwrap_or(0);
        if count == 0 || next == 0 { break; }
        page = next;
        if page > 100 { return Err("Hetzner SSH key list did not terminate".into()); }
    }
    Ok(out)
}
pub async fn hetzner_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let token = hetzner_token(config)?; let mode = sync_mode(config, "hetzner")?; let dry = is_dry(config);
    let desired = trigger_desired(config, secrets);
    let keys: Vec<(String, String)> = desired.iter().map(|(n, v)| ssh_public_key(n, v).map(|k| (n.clone(), k))).collect::<Result<_, _>>()?;
    let client = http_client(); let root = format!("{}/ssh_keys", base(config, "https://api.hetzner.cloud/v1"));
    let remote = hetzner_keys(&client, &base(config, "https://api.hetzner.cloud/v1"), &token).await?;
    let by_name: HashMap<String, (String, String)> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), (hetzner_id(v)?, v.get("public_key").and_then(Value::as_str).unwrap_or("").trim().to_string())))).collect();
    // The update call renames a key but cannot replace its material, so a changed
    // key is deleted and created again. Its numeric id changes, and anything that
    // referenced the old id loses it.
    let (mut created, mut replaced, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, key) in &keys {
            match by_name.get(name) {
                Some((_, current)) if current == key => unchanged += 1,
                Some((id, _)) => {
                    req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Hetzner replace {} failed while deleting the old key: {}", name, e))?;
                    req(client.post(&root).bearer_auth(&token).json(&json!({"name": name, "public_key": key}))).await.map_err(|e| format!("Hetzner replace {} deleted the old key but the new one was rejected: {}", name, e))?;
                    replaced += 1;
                }
                None => { req(client.post(&root).bearer_auth(&token).json(&json!({"name": name, "public_key": key}))).await.map_err(|e| format!("Hetzner create {} failed: {}", name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if keys.iter().any(|(n, _)| n == name) { continue; }
            if let Some((id, _)) = by_name.get(name) { req(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(&token)).await.map_err(|e| format!("Hetzner delete {} failed: {}", name, e))?; } } }
    } else { for (name, key) in &keys { match by_name.get(name) { Some((_, current)) if current == key => unchanged += 1, Some(_) => replaced += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !keys.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = keys.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("Hetzner sync{}: ssh keys created={} replaced={} unchanged={} deleted={}", if dry { " (dry-run)" } else { "" }, created, replaced, unchanged, deleted), managed))
}
pub async fn hetzner_test(config: &Value) -> Result<String, String> {
    let token = hetzner_token(config)?;
    let list = hetzner_keys(&http_client(), &base(config, "https://api.hetzner.cloud/v1"), &token).await?;
    Ok(format!("Hetzner connection OK: {} SSH key(s) visible", list.len()))
}

// ---------- Initial import ----------
fn strip_remote_prefix(config: &Value, name: &str, path_prefix: &str) -> String {
    let without_path = if path_prefix.is_empty() { name } else { name.strip_prefix(path_prefix).map(|s| s.trim_start_matches('/')).unwrap_or(name) };
    local_name(config, without_path)
}
async fn aws_sm_value(client: &crate::http::Client, config: &Value, region: &str, ak: &str, sk: &str, id: &str) -> Result<Option<String>, String> {
    let value = aws_call(client, config, "secretsmanager", region, ak, sk, "secretsmanager.GetSecretValue", &json!({"SecretId": id})).await?;
    Ok(value.get("SecretString").and_then(Value::as_str).map(str::to_string))
}
async fn ssm_values(client: &crate::http::Client, config: &Value, region: &str, ak: &str, sk: &str) -> Result<Vec<(String, String)>, String> {
    let path = ssm_path(config);
    let mut out = Vec::new();
    if path.is_empty() {
        for name in ssm_list(client, config, region, ak, sk).await? {
            let value = aws_call(client, config, "ssm", region, ak, sk, "AmazonSSM.GetParameter", &json!({"Name": name, "WithDecryption": true})).await?;
            if let Some(v) = value.get("Parameter").and_then(|p| p.get("Value")).and_then(Value::as_str) { out.push((name, v.to_string())); }
        }
    } else {
        let mut token = String::new();
        loop {
            let mut payload = json!({"Path": path, "Recursive": true, "WithDecryption": true, "MaxResults": 10});
            if !token.is_empty() { payload["NextToken"] = json!(token); }
            let value = aws_call(client, config, "ssm", region, ak, sk, "AmazonSSM.GetParametersByPath", &payload).await?;
            if let Some(items) = value.get("Parameters").and_then(Value::as_array) {
                for item in items { if let (Some(name), Some(v)) = (item.get("Name").and_then(Value::as_str), item.get("Value").and_then(Value::as_str)) { out.push((name.to_string(), v.to_string())); } }
            }
            token = value.get("NextToken").and_then(Value::as_str).unwrap_or("").to_string();
            if token.is_empty() { break; }
        }
    }
    Ok(out)
}

/// Read remote values for the initial-import modes. Adapters that cannot return
/// plaintext (or have no read API) return an explicit error instead of pretending.
pub async fn pull(kind: &str, config: &Value) -> Result<Vec<(String, String)>, String> {
    match kind {
        "aws_secrets_manager" => {
            let effective = aws_effective_config(config).await?;
            let config = &effective;
            let (region, ak, sk) = aws_creds(config)?;
            let client = http_client();
            let mapping = { let m = cfg(config, "mapping"); if !m.is_empty() { m } else if !cfg(config, "secret_id").is_empty() { "many_to_one" } else { "one_to_one" } };
            if mapping == "many_to_one" {
                let id = cfg(config, "secret_id");
                if id.is_empty() { return Err("aws_secrets_manager many_to_one requires secret_id".into()); }
                let text = aws_sm_value(&client, config, region, ak, sk, id).await?.ok_or("AWS secret has no SecretString")?;
                let value: Value = serde_json::from_str(&text).map_err(|e| format!("AWS secret is not a JSON object: {}", e))?;
                let object = value.as_object().ok_or("AWS secret is not a JSON object")?;
                return Ok(object.iter().map(|(k, v)| (local_name(config, k), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect());
            }
            let mut out = Vec::new();
            for name in aws_sm_list(&client, config, region, ak, sk).await? {
                if let Some(value) = aws_sm_value(&client, config, region, ak, sk, &name).await? { out.push((strip_remote_prefix(config, &name, ""), value)); }
            }
            Ok(out)
        }
        "aws_parameter_store" => {
            let effective = aws_effective_config(config).await?;
            let config = &effective;
            let (region, ak, sk) = aws_creds(config)?;
            let path = ssm_path(config);
            Ok(ssm_values(&http_client(), config, region, ak, sk).await?.into_iter().map(|(name, value)| (strip_remote_prefix(config, &name, &path), value)).collect())
        }
        "1password" | "onepassword" => {
            let (base, token, vault, label, _) = onepassword_config(config)?;
            let client = http_client();
            let mut out = Vec::new();
            for item in onepassword_items(&client, &base, &token, &vault).await? {
                let title = item.get("title").and_then(Value::as_str).unwrap_or("").to_string();
                let id = item.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                if title.is_empty() || id.is_empty() { continue; }
                let text = req(client.get(format!("{}/v1/vaults/{}/items/{}", base, vault, id)).bearer_auth(&token)).await?;
                let detail: Value = serde_json::from_str(&text).map_err(|e| format!("1Password invalid item {}: {}", title, e))?;
                if let Some(value) = onepassword_field(&detail, &label) { out.push((strip_remote_prefix(config, &title, ""), value.to_string())); }
            }
            Ok(out)
        }
        "dokploy" => {
            let (base, key, id, is_app) = dokploy_config(config)?;
            let url = if is_app { format!("{}/api/application.one?applicationId={}", base, form_encode(&id)) } else { format!("{}/api/compose.one?composeId={}", base, form_encode(&id)) };
            let text = req(http_client().get(url).header("x-api-key", &key)).await.map_err(|e| format!("Dokploy read failed: {}", e))?;
            let value: Value = serde_json::from_str(&text).map_err(|e| format!("Dokploy invalid read response: {}", e))?;
            Ok(dotenv_map(value.get("env").and_then(Value::as_str).unwrap_or("")).into_iter().map(|(k, v)| (strip_remote_prefix(config, &k, ""), v)).collect())
        }
        "caprover" => {
            let client = http_client();
            let (api, token) = caprover_auth(&client, config).await?;
            let apps = caprover_apps(&client, &api, &token).await?;
            let app_name = cfg(config, "app_name").trim();
            let app = apps.iter().find(|a| a.get("appName").and_then(Value::as_str) == Some(app_name)).ok_or_else(|| format!("CapRover app {:?} not found", app_name))?;
            Ok(app.get("envVars").and_then(Value::as_array).map(|items| items.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect()).unwrap_or_default())
        }
        "portainer" => {
            let (base, key) = portainer_auth(config)?;
            let client = http_client();
            let stacks = portainer_stacks(&client, &base, &key).await?;
            let wanted_id = config_i64(config, "stack_id");
            let wanted_name = cfg(config, "stack_name");
            let stack = stacks.iter().find(|s| (wanted_id.is_some() && s.get("Id").and_then(Value::as_i64) == wanted_id) || (!wanted_name.is_empty() && s.get("Name").and_then(Value::as_str) == Some(wanted_name))).ok_or("Portainer stack not found")?;
            let id = stack.get("Id").and_then(Value::as_i64).ok_or("Portainer stack has no Id")?;
            let text = req(client.get(format!("{}/api/stacks/{}", base, id)).header("X-API-Key", &key)).await.map_err(|e| format!("Portainer read stack failed: {}", e))?;
            let detail: Value = serde_json::from_str(&text).map_err(|e| format!("Portainer invalid stack response: {}", e))?;
            Ok(detail.get("Env").and_then(Value::as_array).map(|items| items.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("name")?.as_str()?, ""), v.get("value").and_then(Value::as_str).unwrap_or("").to_string()))).collect()).unwrap_or_default())
        }
        "bitbucket" => {
            let base = base(config, "https://api.bitbucket.org/2.0");
            let (workspace, repo) = (cfg(config, "workspace"), cfg(config, "repo_slug"));
            if workspace.is_empty() || repo.is_empty() { return Err("Bitbucket requires workspace and repo_slug".into()); }
            let list = bitbucket_list(&http_client(), &base, workspace, repo, &auth_value(config)?).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "teamcity" => {
            let base = teamcity_base(config)?; let auth = auth_value(config)?; let (kind_scope, locator) = teamcity_scope(config);
            let list = teamcity_list(&http_client(), &base, &auth, &kind_scope, &locator).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("name")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "travisci" => {
            let base = base(config, "https://api.travis-ci.com"); let slug = enc(cfg(config, "repo")); let token = cfg(config, "token");
            if cfg(config, "repo").is_empty() || token.is_empty() { return Err("Travis CI requires repo (owner/name) and token".into()); }
            let list = travis_list(&http_client(), &base, &slug, token).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("name")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "terraform_cloud" => {
            let base = base(config, "https://app.terraform.io/api/v2"); let token = cfg(config, "token"); let workspace_id = cfg(config, "workspace_id");
            if token.is_empty() || workspace_id.is_empty() { return Err("Terraform Cloud requires token and workspace_id".into()); }
            let category = { let c = cfg(config, "category"); if c.is_empty() { "env" } else { c } };
            let list = tfcloud_list(&http_client(), &base, token, workspace_id).await?;
            Ok(list.iter().filter(|v| v.get("attributes").and_then(|a| a.get("category")).and_then(Value::as_str) == Some(category)).filter_map(|v| Some((strip_remote_prefix(config, v.get("attributes")?.get("key")?.as_str()?, ""), v.get("attributes")?.get("value")?.as_str()?.to_string()))).collect())
        }
        "qovery" => {
            let (root, token) = qovery_root(config)?;
            let list = qovery_list(&http_client(), &root, &token).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "laravel_forge" => {
            let (root, token) = forge_root(config)?;
            let env = forge_env(&http_client(), &root, &token).await?;
            Ok(dotenv_map(&env).into_iter().map(|(k, v)| (strip_remote_prefix(config, &k, ""), v)).collect())
        }
        "openwarp" => {
            let (base, token, env) = openwarp_remote(config)?;
            let list = openwarp_list(&http_client(), &base, &token, &env).await?;
            Ok(list.iter().filter(|v| v.get("type").and_then(Value::as_str) != Some("sealed")).filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "octopus_deploy" => {
            let (root, key) = octopus_root(config)?;
            let text = req(http_client().get(&root).header("X-Octopus-ApiKey", &key)).await?;
            let value: Value = serde_json::from_str(&text).map_err(|e| format!("Octopus Deploy invalid response: {}", e))?;
            Ok(value.get("Variables").and_then(Value::as_array).map(|items| items.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("Name")?.as_str()?, ""), v.get("Value")?.as_str()?.to_string()))).collect()).unwrap_or_default())
        }
        "azure_devops" => {
            let (root, auth) = azure_devops_root(config)?;
            let text = req(http_client().get(&root).header("Authorization", &auth).header("Accept", "application/json")).await?;
            let value: Value = serde_json::from_str(&text).map_err(|e| format!("Azure DevOps invalid response: {}", e))?;
            Ok(value.get("variables").and_then(Value::as_object).map(|vars| vars.iter().filter_map(|(k, v)| Some((strip_remote_prefix(config, k, ""), v.get("value")?.as_str()?.to_string()))).collect()).unwrap_or_default())
        }
        "northflank" => {
            let (root, token) = northflank_parts(config)?;
            Ok(northflank_variables(&http_client(), &root, &token).await?.into_iter().map(|(k, v)| (strip_remote_prefix(config, &k, ""), v)).collect())
        }
        "spacelift" => {
            let endpoint = spacelift_endpoint(config)?; let stack = cfg(config, "stack_id");
            if stack.is_empty() { return Err("Spacelift requires stack_id".into()); }
            let client = http_client(); let token = spacelift_auth(&client, &endpoint, config).await?;
            let query = "query($stack: ID!) { stack(id: $stack) { config { id type value writeOnly } } }";
            let data = spacelift_graphql(&client, &endpoint, Some(&token), query, json!({"stack": stack})).await?;
            Ok(data.get("stack").and_then(|s| s.get("config")).and_then(Value::as_array).map(|items| items.iter().filter(|v| v.get("type").and_then(Value::as_str) == Some("ENVIRONMENT_VARIABLE")).filter_map(|v| Some((strip_remote_prefix(config, v.get("id")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect()).unwrap_or_default())
        }
        "rundeck" => {
            let (base, token) = rundeck_parts(config)?;
            let client = http_client(); let keys = rundeck_keys(&client, &base, &token).await?;
            let mut out = Vec::new();
            for key in keys {
                let value = req(client.get(format!("{}/{}", base, enc(&key))).header("X-Rundeck-Auth-Token", &token)).await?;
                out.push((strip_remote_prefix(config, &key, ""), value));
            }
            Ok(out)
        }
        "cloud66" => {
            let (base, token, stack) = cloud66_parts(config)?;
            let list = cloud66_list(&http_client(), &base, &token, &stack).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "humanitec" => {
            let list = humanitec_list(&http_client(), config).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "scaleway_secret_manager" => {
            let (base, region, token, project, path) = scaleway_parts(config)?;
            let client = http_client(); let root = scaleway_root(&base, &region);
            let mut out = Vec::new();
            for secret in scaleway_list(&client, &root, &token, &project, &path).await? {
                let name = secret.get("name").and_then(Value::as_str).unwrap_or("");
                let id = secret.get("id").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() || id.is_empty() { continue; }
                if let Some(value) = scaleway_latest(&client, &root, &token, id).await? { out.push((strip_remote_prefix(config, name, ""), value)); }
            }
            Ok(out)
        }
        "azure_app_configuration" => {
            let (endpoint, host, id, secret) = appconfig_parts(config)?;
            let list = appconfig_list(&http_client(), &endpoint, &host, &id, &secret, &appconfig_label(config)).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("key")?.as_str()?, ""), v.get("value")?.as_str()?.to_string()))).collect())
        }
        "vultr" => {
            let token = vultr_token(config)?;
            let list = vultr_keys(&http_client(), &base(config, "https://api.vultr.com/v2"), &token).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("name")?.as_str()?, ""), v.get("ssh_key")?.as_str()?.to_string()))).collect())
        }
        "hetzner" => {
            let token = hetzner_token(config)?;
            let list = hetzner_keys(&http_client(), &base(config, "https://api.hetzner.cloud/v1"), &token).await?;
            Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("name")?.as_str()?, ""), v.get("public_key")?.as_str()?.to_string()))).collect())
        }
        "linode" => { let list = super::ssh_keys::linode_list(config).await?; Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("label")?.as_str()?, ""), v.get("ssh_key")?.as_str()?.to_string()))).collect()) }
        "digitalocean_ssh" => { let list = super::ssh_keys::digitalocean_list(config).await?; Ok(list.iter().filter_map(|v| Some((strip_remote_prefix(config, v.get("name")?.as_str()?, ""), v.get("public_key")?.as_str()?.to_string()))).collect()) }
#[cfg(not(target_arch = "wasm32"))]
        "ssh" => ssh_file_pull(config).await,
        #[cfg(target_arch = "wasm32")]
        "ssh" => Err("SSH file sync needs the native server: a Worker cannot run ssh".into()),
        "ovh_kms" => {
            let client = ovh_kms_client(config)?;
            let (_, data, _) = ovh_kms_bundle(&client, config).await?;
            Ok(data.into_iter().map(|(k, v)| (strip_remote_prefix(config, &k, ""), v)).collect())
        }
        "keeper" => {
            let records = keeper_records(config).await?;
            Ok(records.into_iter().map(|(title, (_, value))| (strip_remote_prefix(config, &title, ""), value)).collect())
        }
        "huggingface" => {
            let (base_url, token, path) = huggingface_space(config)?;
            if path.ends_with("/secrets") { return Err("Hugging Face Space secrets are write-only, so initial import is not possible; target variables instead".into()); }
            let list = huggingface_space_list(&http_client(), &base_url, &token, &path).await?;
            Ok(list.into_iter().filter_map(|(k, v)| Some((strip_remote_prefix(config, &k, ""), v?))).collect())
        }
        #[cfg(not(target_arch = "wasm32"))]
        "oci_vault" => {
            let client = http_client(); let list = oci_list(&client, config).await?;
            let mut out = Vec::new();
            for item in list {
                let name = item.get("secretName").and_then(Value::as_str).unwrap_or("");
                let id = item.get("id").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() || id.is_empty() { continue; }
                out.push((strip_remote_prefix(config, name, ""), oci_bundle(&client, config, id).await?));
            }
            Ok(out)
        }
        "cursor" => Err("Cursor does not expose secret values, so initial import is not possible".into()),
        "devin" => Err("Devin does not expose secret values, so initial import is not possible".into()),
        "cloudflare_secrets_store" => Err("Cloudflare Secrets Store values are write-only, so initial import is not possible".into()),
        "circleci" => Err("CircleCI does not expose environment variable values, so initial import is not possible".into()),
        _ => Err(format!("initial import is not supported for kind {}", kind)),
    }
}

pub fn is_stateful(kind: &str) -> bool {
    matches!(kind, "trigger" | "instabox" | "boat" | "daytona" | "1password" | "onepassword" | "aws_secrets_manager" | "aws_parameter_store" | "dokploy" | "caprover" | "portainer" | "docker_swarm" | "bitbucket" | "circleci" | "teamcity" | "travisci" | "terraform_cloud" | "qovery" | "laravel_forge" | "openwarp" | "devin" | "cloudflare_secrets_store" | "octopus_deploy" | "azure_devops" | "cursor" | "northflank" | "spacelift" | "rundeck" | "cloud66" | "humanitec" | "ovh_kms" | "scaleway_secret_manager" | "azure_app_configuration" | "vultr" | "hetzner" | "linode" | "digitalocean_ssh" | "ssh" | "keeper" | "oci_vault" | "huggingface")
}
/// Stateful adapters return a report and the remote names they now own.
pub async fn sync_managed(kind: &str, config: &Value, secrets: &[(String, String, String, String)], previous_managed: &[String]) -> Option<Result<(String, Vec<String>), String>> {
    if let Err(e) = validate_naming(config) { return Some(Err(e)); }
    let flat = secret_keys(secrets);
    let pairs = flat.as_slice();
    // Account SSH key APIs reject anything that is not a public key, so they
    // only receive secrets the caller marked as one.
    let ssh_only = super::ssh_keys::only_ssh_keys(&secrets.iter().map(|(_, k, v, t)| (k.clone(), v.clone(), t.clone())).collect::<Vec<_>>());
    let ssh_pairs = ssh_only.as_slice();
    let result = match kind {
        "trigger" => trigger_sync(config, pairs, previous_managed).await,
        "instabox" => instabox_sync(config, pairs, previous_managed).await,
        "boat" => boat_sync(config, pairs, previous_managed).await,
        "daytona" => daytona_sync(config, pairs, previous_managed).await,
        "1password" | "onepassword" => onepassword_sync(config, pairs, previous_managed).await,
        "aws_secrets_manager" => aws_secrets_manager_sync(config, pairs, previous_managed).await,
        "aws_parameter_store" => aws_parameter_store_sync(config, pairs, previous_managed).await,
        "dokploy" => dokploy_sync(config, pairs, previous_managed).await,
        "caprover" => caprover_sync(config, pairs, previous_managed).await,
        "portainer" => portainer_sync(config, pairs, previous_managed).await,
        "docker_swarm" => docker_swarm_sync(config, pairs, previous_managed).await,
        "bitbucket" => bitbucket_sync(config, pairs, previous_managed).await,
        "circleci" => circleci_sync(config, pairs, previous_managed).await,
        "teamcity" => teamcity_sync(config, pairs, previous_managed).await,
        "travisci" => travisci_sync(config, pairs, previous_managed).await,
        "terraform_cloud" => terraform_cloud_sync(config, pairs, previous_managed).await,
        "qovery" => qovery_sync(config, pairs, previous_managed).await,
        "laravel_forge" => laravel_forge_sync(config, pairs, previous_managed).await,
        "openwarp" => openwarp_sync(config, pairs, previous_managed).await,
        "devin" => devin_sync(config, pairs, previous_managed).await,
        "cloudflare_secrets_store" => cloudflare_secrets_store_sync(config, pairs, previous_managed).await,
        "octopus_deploy" => octopus_deploy_sync(config, pairs, previous_managed).await,
        "azure_devops" => azure_devops_sync(config, pairs, previous_managed).await,
        "cursor" => cursor_sync(config, pairs, previous_managed).await,
        "northflank" => northflank_sync(config, pairs, previous_managed).await,
        "spacelift" => spacelift_sync(config, pairs, previous_managed).await,
        "rundeck" => rundeck_sync(config, pairs, previous_managed).await,
        "cloud66" => cloud66_sync(config, pairs, previous_managed).await,
        "humanitec" => humanitec_sync(config, pairs, previous_managed).await,
        "scaleway_secret_manager" => scaleway_sync(config, pairs, previous_managed).await,
        "azure_app_configuration" => azure_app_configuration_sync(config, pairs, previous_managed).await,
        "vultr" => vultr_sync(config, ssh_pairs, previous_managed).await,
        "hetzner" => hetzner_sync(config, ssh_pairs, previous_managed).await,
        "linode" => super::ssh_keys::linode_sync(config, ssh_pairs, previous_managed).await,
        "digitalocean_ssh" => super::ssh_keys::digitalocean_sync(config, ssh_pairs, previous_managed).await,
#[cfg(not(target_arch = "wasm32"))]
        "ssh" => ssh_file_sync(config, secrets, previous_managed).await,
        #[cfg(target_arch = "wasm32")]
        "ssh" => Err("SSH file sync needs the native server: a Worker cannot run ssh".into()),
        "ovh_kms" => ovh_kms_sync(config, pairs, previous_managed).await,
        "keeper" => keeper_sync(config, pairs, previous_managed).await,
#[cfg(not(target_arch = "wasm32"))]
        "oci_vault" => oci_vault_sync(config, pairs, previous_managed).await,
        #[cfg(target_arch = "wasm32")]
        "oci_vault" => Err("OCI Vault needs RSA request signing, which requires the native server".into()),
        "huggingface" => huggingface_sync(config, pairs, previous_managed).await,
        _ => return None,
    };
    Some(result)
}

pub fn has_test(kind: &str) -> bool {
    matches!(kind, "trigger" | "instabox" | "boat" | "daytona" | "aws_secrets_manager" | "aws_parameter_store" | "1password" | "onepassword" | "dokploy" | "caprover" | "portainer" | "docker_swarm" | "bitbucket" | "circleci" | "teamcity" | "travisci" | "terraform_cloud" | "qovery" | "laravel_forge" | "openwarp" | "devin" | "cloudflare_secrets_store" | "octopus_deploy" | "azure_devops" | "cursor" | "northflank" | "spacelift" | "rundeck" | "cloud66" | "humanitec" | "ovh_kms" | "scaleway_secret_manager" | "azure_app_configuration" | "vultr" | "hetzner" | "linode" | "digitalocean_ssh" | "ssh" | "keeper" | "oci_vault" | "huggingface")
}
pub async fn test(kind: &str, config: &Value) -> Result<String, String> {
    match kind {
        "trigger" => trigger_test(config).await,
        "instabox" => instabox_test(config).await,
        "boat" => boat_test(config).await,
        "daytona" => daytona_test(config).await,
        "aws_secrets_manager" => aws_secrets_manager_test(config).await,
        "aws_parameter_store" => aws_parameter_store_test(config).await,
        "1password" | "onepassword" => onepassword_test(config).await,
        "dokploy" => dokploy_test(config).await,
        "caprover" => caprover_test(config).await,
        "portainer" => portainer_test(config).await,
        "docker_swarm" => docker_swarm_test(config).await,
        "bitbucket" => bitbucket_test(config).await,
        "circleci" => circleci_test(config).await,
        "teamcity" => teamcity_test(config).await,
        "travisci" => travisci_test(config).await,
        "terraform_cloud" => terraform_cloud_test(config).await,
        "qovery" => qovery_test(config).await,
        "laravel_forge" => laravel_forge_test(config).await,
        "openwarp" => openwarp_test(config).await,
        "devin" => devin_test(config).await,
        "cloudflare_secrets_store" => cloudflare_secrets_store_test(config).await,
        "octopus_deploy" => octopus_deploy_test(config).await,
        "azure_devops" => azure_devops_test(config).await,
        "cursor" => cursor_test(config).await,
        "northflank" => northflank_test(config).await,
        "spacelift" => spacelift_test(config).await,
        "rundeck" => rundeck_test(config).await,
        "cloud66" => cloud66_test(config).await,
        "humanitec" => humanitec_test(config).await,
        "scaleway_secret_manager" => scaleway_test(config).await,
        "azure_app_configuration" => azure_app_configuration_test(config).await,
        "vultr" => vultr_test(config).await,
        "hetzner" => hetzner_test(config).await,
        "linode" => super::ssh_keys::linode_test(config).await,
        "digitalocean_ssh" => super::ssh_keys::digitalocean_test(config).await,
#[cfg(not(target_arch = "wasm32"))]
        "ssh" => ssh_file_test(config).await,
        #[cfg(target_arch = "wasm32")]
        "ssh" => Err("SSH file sync needs the native server: a Worker cannot run ssh".into()),
        "ovh_kms" => ovh_kms_test(config).await,
        "keeper" => keeper_test(config).await,
#[cfg(not(target_arch = "wasm32"))]
        "oci_vault" => oci_vault_test(config).await,
        #[cfg(target_arch = "wasm32")]
        "oci_vault" => Err("OCI Vault needs RSA request signing, which requires the native server".into()),
        "huggingface" => huggingface_test(config).await,
        _ => Err(format!("connection test is not implemented for kind {}", kind)),
    }
}
fn form_encode(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{:02X}", b),
    }).collect()
}
fn xml_tag(text: &str, name: &str) -> String {
    let open = format!("<{}>", name); let close = format!("</{}>", name);
    text.find(&open).and_then(|i| {
        let start = i + open.len();
        text[start..].find(&close).map(|j| text[start..start + j].to_string())
    }).unwrap_or_default().replace("&amp;", "&")
}
/// Exchange an IAM role for temporary STS credentials.
pub async fn sts_assume_role(config: &Value) -> Result<Value, String> {
    let region = cfg(config, "region"); let ak = cfg(config, "access_key_id"); let sk = cfg(config, "secret_access_key");
    let role_arn = cfg(config, "role_arn"); let session = { let s = cfg(config, "session_name"); if s.is_empty() { "openwarp" } else { s } };
    if region.is_empty() || ak.is_empty() || sk.is_empty() || role_arn.is_empty() {
        return Err("aws_iam lease requires region, access_key_id, secret_access_key and role_arn".into());
    }
    let duration = config.get("duration_secs").and_then(|v| v.as_i64()).unwrap_or(3600).clamp(900, 43200);
    let endpoint = { let e = cfg(config, "sts_endpoint"); if e.is_empty() { cfg(config, "endpoint") } else { e } };
    let (url, host_header, path) = if endpoint.is_empty() {
        (format!("https://sts.{}.amazonaws.com", region), format!("sts.{}.amazonaws.com", region), "/".to_string())
    } else {
        let u = reqwest::Url::parse(endpoint).map_err(|e| format!("invalid STS endpoint: {}", e))?;
        let host = u.host_str().ok_or("STS endpoint has no host")?;
        let host_header = match u.port() { Some(p) => format!("{}:{}", host, p), None => host.to_string() };
        (endpoint.trim_end_matches('/').to_string(), host_header, if u.path().is_empty() { "/".into() } else { u.path().to_string() })
    };
    let body = format!("Action=AssumeRole&Version=2011-06-15&RoleArn={}&RoleSessionName={}&DurationSeconds={}",
        form_encode(role_arn), form_encode(session), duration);
    let amzdate = chrono_now(); let date = amzdate[..8].to_string();
    let content_type = "application/x-www-form-urlencoded; charset=utf-8";
    let payload_hash = hex(&Sha256::digest(body.as_bytes()));
    let canonical = format!("POST\n{}\n\ncontent-type:{}\nhost:{}\nx-amz-date:{}\n\ncontent-type;host;x-amz-date\n{}",
        path, content_type, host_header, amzdate, payload_hash);
    let scope = format!("{}/{}/sts/aws4_request", date, region);
    let to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amzdate, scope, hex(&Sha256::digest(canonical.as_bytes())));
    let k_date = hmac(format!("AWS4{}", sk).as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, b"sts");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, to_sign.as_bytes()));
    let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date, Signature={}", ak, scope, signature);
    let text = req(http_client().post(&url).header("Content-Type", content_type).header("X-Amz-Date", &amzdate)
        .header("Authorization", auth).body(body)).await.map_err(|e| format!("STS AssumeRole failed: {}", e))?;
    let access_key_id = xml_tag(&text, "AccessKeyId");
    let secret_access_key = xml_tag(&text, "SecretAccessKey");
    let session_token = xml_tag(&text, "SessionToken");
    if access_key_id.is_empty() || secret_access_key.is_empty() || session_token.is_empty() {
        return Err(format!("STS AssumeRole response is missing credentials: {}", text.chars().take(400).collect::<String>()));
    }
    Ok(json!({
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "session_token": session_token,
        "expiration": xml_tag(&text, "Expiration"),
        "region": region,
    }))
}
fn lease_base(config: &Value, default: &str) -> Result<String, String> {
    let raw = { let b = cfg(config, "base_url"); if b.is_empty() { default } else { b } };
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid base_url: {}", e))?;
    if url.scheme() != "https" && url.scheme() != "http" { return Err("base_url must be an http(s) URL".into()); }
    let host = url.host_str().ok_or("base_url has no host")?;
    // Production refuses loopback and literal IPs. Tests and local overrides use them.
    let production = crate::envcfg::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false) || config.get("require_public_host").and_then(|v| v.as_bool()).unwrap_or(false);
    let private_ok = crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false);
    if production && !private_ok && (host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok()) {
        return Err("base_url must name a public host; loopback and IP hosts are refused".into());
    }
    Ok(raw.trim_end_matches('/').to_string())
}
fn key_ref_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}
/// Create a short-lived OpenRouter inference key from a management key.
/// `https://openrouter.ai/docs/api/api-reference/api-keys/create-a-new-api-key`
pub async fn openrouter_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
    let management_key = cfg(config, "management_key");
    if management_key.is_empty() { return Err("openrouter lease requires config.management_key".into()); }
    if name.is_empty() || name.len() > 256 { return Err("openrouter key name must be 1 to 256 characters".into()); }
    let base = lease_base(config, "https://openrouter.ai/api/v1")?;
    let mut body = serde_json::Map::new();
    body.insert("name".into(), json!(name));
    if let Some(limit) = config.get("limit").filter(|v| v.is_number()) { body.insert("limit".into(), limit.clone()); }
    let reset = cfg(config, "limit_reset");
    if !reset.is_empty() {
        if !matches!(reset, "daily" | "weekly" | "monthly") { return Err("openrouter limit_reset must be daily, weekly or monthly".into()); }
        body.insert("limit_reset".into(), json!(reset));
    }
    let workspace = cfg(config, "workspace_id");
    if !workspace.is_empty() { body.insert("workspace_id".into(), json!(workspace)); }
    // OpenRouter rejects minute-precision timestamps; seconds are required.
    let expires = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + ttl_secs.clamp(60, 30 * 86400);
    body.insert("expires_at".into(), json!(format!("{}Z", chrono_now_at(expires))));
    let text = req(http_client().post(format!("{}/keys", base)).bearer_auth(management_key).json(&Value::Object(body))).await
        .map_err(|e| format!("OpenRouter key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("OpenRouter key response is not JSON: {}", e))?;
    let key = parsed.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let hash = parsed.get("data").and_then(|d| d.get("hash")).and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() || !key_ref_ok(hash) { return Err("OpenRouter key response is missing the key or its hash".into()); }
    Ok(json!({"key": key, "hash": hash, "name": parsed["data"]["name"], "limit": parsed["data"]["limit"], "expires_at": parsed["data"]["expires_at"]}))
}
/// Delete the child key. The management key stays in the request; only the hash is stored on the lease.
pub async fn openrouter_revoke_key(base_url: &str, management_key: &str, hash: &str) -> Result<(), String> {
    if !key_ref_ok(hash) { return Err("openrouter key hash is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://openrouter.ai/api/v1")?;
    req(http_client().delete(format!("{}/keys/{}", base, hash)).bearer_auth(management_key)).await
        .map_err(|e| format!("OpenRouter key revocation failed: {}", e))?;
    Ok(())
}
/// Issue a Resend sending key. `https://resend.com/docs/api-reference/api-keys/create-api-key`
pub async fn resend_create_key(config: &Value, name: &str) -> Result<Value, String> {
    let api_key = cfg(config, "api_key");
    if api_key.is_empty() { return Err("resend lease requires config.api_key".into()); }
    if name.is_empty() || name.len() > 50 { return Err("resend key name must be 1 to 50 characters".into()); }
    let permission = { let p = cfg(config, "permission"); if p.is_empty() { "sending_access" } else { p } };
    if !matches!(permission, "sending_access" | "full_access") { return Err("resend permission must be sending_access or full_access".into()); }
    let mut body = serde_json::Map::new(); body.insert("name".into(), json!(name)); body.insert("permission".into(), json!(permission));
    let domain_id = cfg(config, "domain_id");
    if !domain_id.is_empty() {
        if permission != "sending_access" { return Err("resend domain_id is only valid with sending_access".into()); }
        body.insert("domain_id".into(), json!(domain_id));
    }
    let base = lease_base(config, "https://api.resend.com")?;
    let text = req(http_client().post(format!("{}/api-keys", base)).bearer_auth(api_key).json(&Value::Object(body))).await
        .map_err(|e| format!("Resend key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Resend key response is not JSON: {}", e))?;
    let token = parsed.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if token.is_empty() || !key_ref_ok(id) { return Err("Resend key response is missing the token or its id".into()); }
    Ok(json!({"token": token, "id": id}))
}
pub async fn resend_revoke_key(base_url: &str, api_key: &str, id: &str) -> Result<(), String> {
    if !key_ref_ok(id) { return Err("resend key id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.resend.com")?;
    req(http_client().delete(format!("{}/api-keys/{}", base, id)).bearer_auth(api_key)).await
        .map_err(|e| format!("Resend key revocation failed: {}", e))?;
    Ok(())
}
/// Issue an OpenAI project service-account key.
/// `https://developers.openai.com/api/reference/resources/admin` service-account key create.
pub async fn openai_create_key(config: &Value, name: &str, ttl_secs: i64) -> Result<Value, String> {
    let admin_key = cfg(config, "admin_key");
    let project_id = cfg(config, "project_id");
    let service_account_id = cfg(config, "service_account_id");
    if admin_key.is_empty() || !key_ref_ok(project_id) || !key_ref_ok(service_account_id) {
        return Err("openai lease requires config.admin_key, project_id and service_account_id".into());
    }
    let mut body = serde_json::Map::new();
    if !name.is_empty() { body.insert("name".into(), json!(name)); }
    body.insert("expires_in_seconds".into(), json!(ttl_secs.clamp(60, 31_536_000)));
    if let Some(scopes) = config.get("scopes").filter(|v| v.is_array()) { body.insert("scopes".into(), scopes.clone()); }
    let base = lease_base(config, "https://api.openai.com/v1")?;
    let url = format!("{}/organization/projects/{}/service_accounts/{}/api_keys", base, project_id, service_account_id);
    let text = req(http_client().post(url).bearer_auth(admin_key).json(&Value::Object(body))).await
        .map_err(|e| format!("OpenAI key creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("OpenAI key response is not JSON: {}", e))?;
    let value = parsed.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if value.is_empty() || !key_ref_ok(id) { return Err("OpenAI key response is missing the value or its id".into()); }
    Ok(json!({"value": value, "id": id, "expires_at": parsed["expires_at"]}))
}
pub async fn openai_revoke_key(base_url: &str, admin_key: &str, project_id: &str, key_id: &str) -> Result<(), String> {
    if !key_ref_ok(project_id) || !key_ref_ok(key_id) { return Err("openai project or key id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://api.openai.com/v1")?;
    req(http_client().delete(format!("{}/organization/projects/{}/api_keys/{}", base, project_id, key_id)).bearer_auth(admin_key)).await
        .map_err(|e| format!("OpenAI key revocation failed: {}", e))?;
    Ok(())
}
const HF_PERMISSIONS: &[&str] = &["repo.content.read","repo.contribute.write","repo.write","inference.serverless.write","inference.endpoints.infer.write","inference.endpoints.write","org.read","org.write","collection.read","collection.write","resourceGroup.write","job.write","org.serviceAccounts.read","org.serviceAccounts.write","org.auditLog.write"];
/// Issue a fine-grained token for a Hugging Face organization service account.
/// `POST /api/organizations/{org}/service-accounts/{id}/tokens` (Hub OpenAPI).
pub async fn huggingface_create_token(config: &Value, name: &str) -> Result<Value, String> {
    let token = cfg(config, "token");
    let org = cfg(config, "org");
    let service_account_id = cfg(config, "service_account_id");
    if token.is_empty() || !key_ref_ok(org) || !key_ref_ok(service_account_id) {
        return Err("huggingface lease requires config.token, org and service_account_id".into());
    }
    let display = if name.is_empty() { "openwarp" } else { name };
    if display.len() > 100 { return Err("huggingface token name must be 1 to 100 characters".into()); }
    let mut body = serde_json::Map::new();
    body.insert("displayName".into(), json!(display));
    if let Some(permissions) = config.get("permissions").and_then(|v| v.as_array()) {
        if permissions.iter().any(|p| !HF_PERMISSIONS.contains(&p.as_str().unwrap_or(""))) {
            return Err("huggingface permissions contain a value the Hub API does not accept".into());
        }
        body.insert("permissions".into(), json!(permissions));
    }
    let base = lease_base(config, "https://huggingface.co")?;
    let url = format!("{}/api/organizations/{}/service-accounts/{}/tokens", base, org, service_account_id);
    let text = req(http_client().post(url).bearer_auth(token).json(&Value::Object(body))).await
        .map_err(|e| format!("Hugging Face token creation failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("Hugging Face token response is not JSON: {}", e))?;
    let secret = parsed.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let id = parsed.get("tokenInfo").and_then(|v| v.get("_id")).and_then(|v| v.as_str()).unwrap_or("");
    if secret.is_empty() || !key_ref_ok(id) { return Err("Hugging Face token response is missing the token or its id".into()); }
    Ok(json!({"token": secret, "id": id}))
}
pub async fn huggingface_revoke_token(base_url: &str, token: &str, org: &str, service_account_id: &str, token_id: &str) -> Result<(), String> {
    if !key_ref_ok(org) || !key_ref_ok(service_account_id) || !key_ref_ok(token_id) { return Err("huggingface org, service account or token id is missing".into()); }
    let base = lease_base(&json!({"base_url": base_url}), "https://huggingface.co")?;
    req(http_client().delete(format!("{}/api/organizations/{}/service-accounts/{}/tokens/{}", base, org, service_account_id, token_id)).bearer_auth(token)).await
        .map_err(|e| format!("Hugging Face token revocation failed: {}", e))?;
    Ok(())
}
fn chrono_now() -> String { chrono_now_at(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64) }
fn chrono_now_at(secs: i64) -> String {
    // YYYYMMDDTHHMMSSZ from unix time without chrono dep
    let days = secs.div_euclid(86400); let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem/3600, (rem%3600)/60, rem%60);
    let (y, mo, d) = civil(days);
    format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", y, mo, d, h, mi, s)
}
fn civil(z: i64) -> (i64, u32, u32) { let z = z + 719468; let era = z.div_euclid(146097); let doe = z.rem_euclid(146097); let yoe = (doe - doe/1460 + doe/36524 - doe/146096)/365; let y = yoe + era*400; let doy = doe - (365*yoe + yoe/4 - yoe/100); let mp = (5*doy + 2)/153; let d = (doy - (153*mp+2)/5 + 1) as u32; let m = if mp < 10 { mp+3 } else { mp-9 } as u32; (if m <= 2 { y+1 } else { y }, m, d) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<(String, String, String)>>>;
    type FullCalls = Arc<Mutex<Vec<(String, String, String, String)>>>;

    fn header_end(buf: &[u8]) -> Option<usize> { buf.windows(4).position(|w| w == b"\r\n\r\n") }
    fn content_length(head: &str) -> usize { head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse().ok() } else { None } }).unwrap_or(0) }

    fn mock_routes(items: &[(&str, u16, &str)]) -> Vec<(String, u16, String)> { items.iter().map(|(pattern, status, body)| (pattern.to_string(), *status, body.to_string())).collect() }

    /// Mock server that matches a pattern against "METHOD PATH HEADERS" and records
    /// the method, path, raw headers and body of every request.
    fn start_mock_routes(routes: Vec<(String, u16, String)>) -> (String, FullCalls) {
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
                    if let Some(end) = header_end(&buf) {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        if buf.len() >= end + 4 + content_length(&head) { break; }
                    }
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
                let status_line = match status { 201 => "201 Created", 204 => "204 No Content", 400 => "400 Bad Request", 404 => "404 Not Found", _ => "200 OK" };
                let _ = stream.write_all(format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status_line, payload.len(), payload).as_bytes());
            }
        });
        (format!("http://{}", addr), calls)
    }

    fn start_mock() -> (String, Calls) { start_mock_with(None) }

    fn start_mock_with(envvars: Option<Value>) -> (String, Calls) {
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
                    if let Some(end) = header_end(&buf) {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        if buf.len() >= end + 4 + content_length(&head) { break; }
                    }
                }
                let end = header_end(&buf).unwrap_or(buf.len());
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let request = head.lines().next().unwrap_or("").to_string();
                let mut parts = request.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let len = content_length(&head);
                let body = String::from_utf8_lossy(&buf[end + 4..(end + 4 + len).min(buf.len())]).to_string();
                sink.lock().unwrap().push((method.clone(), path.clone(), body));
                let (status, payload) = if method == "GET" && path.contains("/envvars") {
                        ("200 OK", envvars.clone().unwrap_or(json!([])).to_string())
                    } else if method == "GET" && path.contains("/environments") {
                        ("200 OK", json!({"environments": [{"id": "env-1", "name": "base", "envContents": "OLD=1\n"}]}).to_string())
                    } else if method == "POST" && path == "/" {
                        ("200 OK", "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>secret-key</SecretAccessKey><SessionToken>session-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>".to_string())
                    } else if method == "GET" && path.contains("/secret") {
                        ("200 OK", json!({"items": [{"id": "sec-1", "name": "OLD"}]}).to_string())
                    } else if method == "GET" { ("200 OK", json!({"items": [{"name": "OLD"}]}).to_string()) }
                    else if method == "DELETE" { ("204 No Content", String::new()) }
                    else if method == "POST" && path.ends_with("/secret") { ("201 Created", json!({"id": "sec-2", "name": "API_KEY"}).to_string()) }
                    else { ("200 OK", json!({"items": []}).to_string()) };
                let _ = stream.write_all(format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, payload.len(), payload).as_bytes());
            }
        });
        (format!("http://{}", addr), calls)
    }

    #[tokio::test]
    async fn instabox_mirror_imports_changes_and_prunes_only_managed_names() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "ibk_test", "org": "team", "base_url": base, "hosts": ["api.example.com"], "mode": "mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string()), ("NEW_KEY".to_string(), "v2".to_string())];
        let (report, managed) = instabox_sync(&config, &secrets, &["OLD".to_string()]).await.expect("sync");
        assert!(report.contains("imported=2"), "{}", report);
        assert!(managed.contains(&"API_KEY".to_string()));
        let calls = calls.lock().unwrap();
        let import = calls.iter().find(|(m, p, _)| m == "POST" && p.ends_with("/import")).expect("import call");
        let body: Value = serde_json::from_str(&import.2).expect("json body");
        assert_eq!(body["delivery"], "proxy");
        assert_eq!(body["values"]["API_KEY"], "v1");
        assert!(calls.iter().any(|(m, p, _)| m == "DELETE" && p.ends_with("/OLD")), "mirror should delete the previously managed name");
        assert!(!calls.iter().any(|(m, p, _)| m == "DELETE" && p.ends_with("/NEW_KEY")), "mirror must not delete names it does not own");
    }

    #[tokio::test]
    async fn instabox_dry_run_never_mutates() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "ibk_test", "org": "team", "base_url": base, "dry_run": true, "allow_all_hosts": true});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = instabox_sync(&config, &secrets, &[]).await.expect("dry run");
        assert!(report.contains("dry-run"), "{}", report);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|(m, _, _)| m == "GET"), "dry run must only read: {:?}", *calls);
    }

    #[tokio::test]
    async fn boat_sync_sets_vars_and_prunes_only_managed_names() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "boat_test", "environment": "base", "org": "team", "base_url": base, "mode": "mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = boat_sync(&config, &secrets, &["OLD".to_string()]).await.expect("boat sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, p, _)| m == "PUT" && (p.ends_with("/vars/API_KEY") || p.contains("/vars/API_KEY?"))).expect("var put");
        assert!(put.1.contains("org=team"), "organisation scope must be sent on mutations: {}", put.1);
        let body: Value = serde_json::from_str(&put.2).expect("json body");
        assert_eq!(body["value"], "v1");
        assert!(calls.iter().any(|(m, p, _)| m == "DELETE" && (p.ends_with("/vars/OLD") || p.contains("/vars/OLD?"))), "mirror should remove the previously managed variable");
    }

    #[tokio::test]
    async fn boat_dry_run_never_mutates() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "boat_test", "environment": "base", "base_url": base, "dry_run": true});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = boat_sync(&config, &secrets, &[]).await.expect("boat dry run");
        assert!(report.contains("dry-run"), "{}", report);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|(m, _, _)| m == "GET"), "dry run must only read: {:?}", *calls);
    }

    #[tokio::test]
    async fn daytona_sync_creates_secrets_prunes_and_mounts() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "dtn_test", "base_url": base, "mode": "mirror", "sandbox": "sb-1"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = daytona_sync(&config, &secrets, &["OLD".to_string()]).await.expect("daytona sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().any(|(m, p, _)| m == "POST" && p.ends_with("/secret")), "new secret should be created");
        assert!(calls.iter().any(|(m, p, _)| m == "DELETE" && p.ends_with("/secret/sec-1")), "mirror should delete the previously managed secret");
        let mount = calls.iter().find(|(m, p, _)| m == "PUT" && p.ends_with("/sandbox/sb-1/secrets")).expect("sandbox mount");
        let body: Value = serde_json::from_str(&mount.2).expect("json body");
        assert!(body["secrets"].as_array().unwrap().iter().any(|m| m.get("API_KEY").is_some()));
    }

    #[tokio::test]
    async fn daytona_dry_run_never_mutates() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "dtn_test", "base_url": base, "dry_run": true});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = daytona_sync(&config, &secrets, &[]).await.expect("daytona dry run");
        assert!(report.contains("dry-run"), "{}", report);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|(m, _, _)| m == "GET"), "dry run must only read: {:?}", *calls);
    }

    #[tokio::test]
    async fn instabox_rejects_reserved_names() {
        let config = json!({"api_key": "ibk_test", "org": "team", "base_url": "http://127.0.0.1:1", "allow_all_hosts": true});
        let secrets = vec![("PATH".to_string(), "/usr/bin".to_string())];
        let error = instabox_sync(&config, &secrets, &[]).await.expect_err("reserved name");
        assert!(error.contains("reserves"), "{}", error);
    }

    #[tokio::test]
    async fn instabox_empty_environment_makes_no_import() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "ibk_test", "org": "team", "base_url": base, "allow_all_hosts": true});
        let (report, managed) = instabox_sync(&config, &[], &[]).await.expect("empty sync");
        assert!(managed.is_empty());
        assert!(report.contains("imported=0"), "{}", report);
        assert!(!calls.lock().unwrap().iter().any(|(m, _, _)| m == "POST"), "an empty environment must not call import");
    }

    #[tokio::test]
    async fn instabox_rejects_names_the_api_cannot_store() {
        let config = json!({"api_key": "ibk_test", "org": "team", "base_url": "http://127.0.0.1:1", "allow_all_hosts": true});
        let secrets = vec![("not-a-valid-name".to_string(), "v".to_string())];
        let error = instabox_sync(&config, &secrets, &[]).await.expect_err("invalid name");
        assert!(error.contains("invalid secret names"), "{}", error);
    }

    #[tokio::test]
    async fn instabox_proxy_requires_an_explicit_host_list() {
        let config = json!({"api_key": "ibk_test", "org": "team", "base_url": "http://127.0.0.1:1"});
        let secrets = vec![("API_KEY".to_string(), "v".to_string())];
        let error = instabox_sync(&config, &secrets, &[]).await.expect_err("missing hosts");
        assert!(error.contains("allow_all_hosts"), "{}", error);
    }

    #[test]
    fn boat_query_encoder_uses_utf8_bytes() {
        assert_eq!(enc("équipe"), "%C3%A9quipe");
        assert_eq!(enc("a b/c"), "a%20b%2Fc");
    }

    #[tokio::test]
    async fn trigger_mirror_prunes_a_name_without_a_value() {
        let (base, calls) = start_mock_with(Some(json!([{"name": "OLD", "value": "1"}, {"name": "NOVALUE"}])));
        let config = json!({"token": "tr_pat_test", "project_ref": "proj", "target_env": "prod", "base_url": base, "mode": "mirror"});
        let secrets = vec![("API_KEY".to_string(), "v".to_string())];
        let (report, _) = trigger_sync(&config, &secrets, &["NOVALUE".to_string()]).await.expect("trigger sync");
        assert!(report.contains("deleted=1"), "{}", report);
        assert!(calls.lock().unwrap().iter().any(|(m, p, _)| m == "DELETE" && p.ends_with("/NOVALUE")), "a name without a value must still be pruned");
    }

    #[tokio::test]
    async fn sts_assume_role_returns_temporary_credentials() {
        let (base, calls) = start_mock();
        let config = json!({
            "region": "us-east-1", "access_key_id": "AKIAEXAMPLEKEY00000", "secret_access_key": "secret",
            "role_arn": "arn:aws:iam::123456789012:role/openwarp", "session_name": "test", "endpoint": base
        });
        let creds = sts_assume_role(&config).await.expect("assume role");
        assert_eq!(creds["access_key_id"], "ASIAEXAMPLE");
        assert_eq!(creds["secret_access_key"], "secret-key");
        assert_eq!(creds["session_token"], "session-token");
        let calls = calls.lock().unwrap();
        let call = calls.iter().find(|(m, p, _)| m == "POST" && p == "/").expect("STS call");
        assert!(call.2.contains("Action=AssumeRole"), "{}", call.2);
        assert!(call.2.contains("RoleArn=arn%3Aaws%3Aiam"), "{}", call.2);
    }

    #[tokio::test]
    async fn openrouter_lease_creates_and_revokes_by_hash() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("POST /keys", 201, r#"{"key":"sk-or-v1-child","data":{"hash":"abc123hash","name":"lease","limit":5,"expires_at":"2030-01-01T00:00:00Z"}}"#),
            ("DELETE /keys/abc123hash", 200, r#"{"deleted":true}"#),
        ]));
        let config = json!({"management_key": "sk-or-mgmt", "limit": 5, "limit_reset": "monthly", "base_url": base});
        let issued = openrouter_create_key(&config, "lease", 3600).await.expect("create");
        assert_eq!(issued["key"], "sk-or-v1-child");
        assert_eq!(issued["hash"], "abc123hash");
        openrouter_revoke_key(&base, "sk-or-mgmt", "abc123hash").await.expect("revoke");
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/keys").expect("create call");
        assert!(create.2.contains("Bearer sk-or-mgmt"), "management key must authenticate the create");
        let body: Value = serde_json::from_str(&create.3).expect("json");
        assert_eq!(body["name"], "lease");
        assert_eq!(body["limit"], 5);
        assert_eq!(body["limit_reset"], "monthly");
        assert!(body["expires_at"].as_str().unwrap_or("").ends_with("Z"));
        assert!(calls.iter().any(|(m, p, h, _)| m == "DELETE" && p == "/keys/abc123hash" && h.contains("Bearer sk-or-mgmt")));
    }

    #[tokio::test]
    async fn key_leases_reject_a_loopback_base_url() {
        let err = openrouter_create_key(&json!({"management_key": "k", "base_url": "http://127.0.0.1:9", "require_public_host": true}), "lease", 3600).await.unwrap_err();
        assert!(err.contains("public host"), "{}", err);
        let err = resend_create_key(&json!({"api_key": "re_parent", "base_url": "http://localhost:9", "require_public_host": true}), "lease").await.unwrap_err();
        assert!(err.contains("public host"), "{}", err);
    }

    #[tokio::test]
    async fn resend_and_openai_leases_create_and_revoke() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("POST /api-keys", 201, r#"{"id":"key-1","token":"re_child"}"#),
            ("DELETE /api-keys/key-1", 200, r#"{"deleted":true}"#),
            ("POST /organization/projects/proj_1/service_accounts/svc_1/api_keys", 200, r#"{"id":"key_abc","value":"sk-child","expires_at":1700000000}"#),
            ("DELETE /organization/projects/proj_1/api_keys/key_abc", 200, r#"{"deleted":true}"#),
        ]));
        let resend = resend_create_key(&json!({"api_key": "re_parent", "permission": "sending_access", "domain_id": "dom_1", "base_url": base}), "mail").await.expect("resend");
        assert_eq!(resend["token"], "re_child");
        resend_revoke_key(&base, "re_parent", resend["id"].as_str().unwrap()).await.expect("resend revoke");
        let openai = openai_create_key(&json!({"admin_key": "sk-admin", "project_id": "proj_1", "service_account_id": "svc_1", "scopes": ["api.responses.write"], "base_url": base}), "app", 3600).await.expect("openai");
        assert_eq!(openai["value"], "sk-child");
        openai_revoke_key(&base, "sk-admin", "proj_1", openai["id"].as_str().unwrap()).await.expect("openai revoke");
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/api-keys").expect("resend create");
        let body: Value = serde_json::from_str(&create.3).unwrap();
        assert_eq!(body["permission"], "sending_access");
        assert_eq!(body["domain_id"], "dom_1");
        let openai_body: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.contains("/service_accounts/")).unwrap().3).unwrap();
        assert_eq!(openai_body["expires_in_seconds"], 3600);
        assert_eq!(openai_body["scopes"][0], "api.responses.write");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/organization/projects/proj_1/api_keys/key_abc"));
    }

    #[tokio::test]
    async fn huggingface_lease_creates_and_deletes_a_service_account_token() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("POST /api/organizations/acme/service-accounts/sa_1/tokens", 201, r#"{"token":"hf_child","tokenInfo":{"_id":"tok_1","displayName":"lease","createdAt":"2026-01-01T00:00:00Z","repoIds":[],"repoPermissions":[],"endpointPatterns":[],"skipNetworkSecurity":false}}"#),
            ("DELETE /api/organizations/acme/service-accounts/sa_1/tokens/tok_1", 204, ""),
        ]));
        let issued = huggingface_create_token(&json!({"token": "hf_admin", "org": "acme", "service_account_id": "sa_1", "permissions": ["repo.content.read"], "base_url": base}), "lease").await.expect("create");
        assert_eq!(issued["token"], "hf_child");
        huggingface_revoke_token(&base, "hf_admin", "acme", "sa_1", issued["id"].as_str().unwrap()).await.expect("revoke");
        let calls = calls.lock().unwrap().clone();
        let body: Value = serde_json::from_str(&calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/tokens")).unwrap().3).unwrap();
        assert_eq!(body["displayName"], "lease");
        assert_eq!(body["permissions"][0], "repo.content.read");
        assert!(calls.iter().any(|(m, p, h, _)| m == "DELETE" && p.ends_with("/tokens/tok_1") && h.contains("Bearer hf_admin")));
        let err = huggingface_create_token(&json!({"token": "hf_admin", "org": "acme", "service_account_id": "sa_1", "permissions": ["not.a.permission"]}), "lease").await.unwrap_err();
        assert!(err.contains("does not accept"), "{}", err);
    }

    #[tokio::test]
    async fn daytona_deduplicates_a_name_that_appears_on_two_paths() {
        let (base, calls) = start_mock();
        let config = json!({"api_key": "dtn_test", "base_url": base});
        let secrets = vec![("API_KEY".to_string(), "one".to_string()), ("API_KEY".to_string(), "two".to_string())];
        daytona_sync(&config, &secrets, &[]).await.expect("sync");
        let posts = calls.lock().unwrap().iter().filter(|(m, p, _)| m == "POST" && p.ends_with("/secret")).count();
        assert_eq!(posts, 1, "the same remote name must be created once");
    }

    #[test]
    fn merge_pairs_preserves_unmanaged_values_and_counts() {
        let current = HashMap::from([("KEEP".to_string(), "1".to_string()), ("OLD".to_string(), "2".to_string())]);
        let desired = vec![("KEEP".to_string(), "1".to_string()), ("NEW".to_string(), "3".to_string())];
        let (merged, created, updated, unchanged, deleted) = merge_pairs(&current, &desired, &["OLD".to_string()], true);
        assert_eq!((created, updated, unchanged, deleted), (1, 0, 1, 1));
        assert_eq!(merged.get("KEEP").map(String::as_str), Some("1"));
        assert_eq!(merged.get("NEW").map(String::as_str), Some("3"));
        assert!(!merged.contains_key("OLD"));
    }

    #[test]
    fn dotenv_render_quotes_values_that_need_it() {
        let map = BTreeMap::from([("PLAIN".to_string(), "abc-123".to_string()), ("SPACED".to_string(), "a b".to_string())]);
        let text = dotenv_render(&map);
        assert!(text.contains("PLAIN=abc-123\n"));
        assert!(text.contains("SPACED='a b'\n"));
    }

    #[tokio::test]
    async fn aws_secrets_manager_one_to_one_creates_and_prunes() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("secretsmanager.ListSecrets", 200, "{\"SecretList\":[{\"Name\":\"OLD\"}]}"),
            ("secretsmanager.PutSecretValue", 200, "{}"),
            ("secretsmanager.DeleteSecret", 200, "{}"),
        ]));
        let config = json!({"region":"us-east-1","access_key_id":"AKIA","secret_access_key":"secret","session_token":"session-token","endpoint":base,"mapping":"one_to_one","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = aws_secrets_manager_sync(&config, &secrets, &["OLD".to_string()]).await.expect("aws sm sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(_, _, head, _)| head.contains("secretsmanager.PutSecretValue")).expect("put call");
        assert!(put.2.to_lowercase().contains("x-amz-security-token: session-token"), "{}", put.2);
        assert!(put.3.contains("\"SecretId\":\"API_KEY\""), "{}", put.3);
        let del = calls.iter().find(|(_, _, head, _)| head.contains("secretsmanager.DeleteSecret")).expect("delete call");
        assert!(del.3.contains("\"SecretId\":\"OLD\""), "{}", del.3);
    }

    #[tokio::test]
    async fn aws_secrets_manager_many_to_one_creates_a_missing_secret() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("secretsmanager.UpdateSecret", 400, "{\"__type\":\"ResourceNotFoundException\",\"message\":\"not found\"}"),
            ("secretsmanager.CreateSecret", 200, "{}"),
        ]));
        let config = json!({"region":"us-east-1","access_key_id":"AKIA","secret_access_key":"secret","endpoint":base,"secret_id":"app/prod","prefix":"APP_","suffix":"_V1"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (_report, managed) = aws_secrets_manager_sync(&config, &secrets, &[]).await.expect("aws sm sync");
        assert!(managed.is_empty());
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(_, _, head, _)| head.contains("secretsmanager.CreateSecret")).expect("create call");
        assert!(create.3.contains("\"Name\":\"app/prod\""), "{}", create.3);
        let body: Value = serde_json::from_str(&create.3).expect("json body");
        let nested: Value = serde_json::from_str(body["SecretString"].as_str().expect("secret string")).expect("nested json");
        assert_eq!(nested["APP_API_KEY_V1"], "v1");
    }

    #[tokio::test]
    async fn aws_parameter_store_writes_secure_strings_under_the_path() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("AmazonSSM.GetParametersByPath", 200, "{\"Parameters\":[]}"),
            ("AmazonSSM.PutParameter", 200, "{}"),
        ]));
        let config = json!({"region":"us-east-1","access_key_id":"AKIA","secret_access_key":"secret","endpoint":base,"path_prefix":"/app/prod"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = aws_parameter_store_sync(&config, &secrets, &[]).await.expect("ssm sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["/app/prod/API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(_, _, head, _)| head.contains("AmazonSSM.PutParameter")).expect("put call");
        let body: Value = serde_json::from_str(&put.3).expect("json body");
        assert_eq!(body["Name"], "/app/prod/API_KEY");
        assert_eq!(body["Type"], "SecureString");
        assert_eq!(body["Overwrite"], true);
    }

    #[tokio::test]
    async fn onepassword_creates_items_and_prunes_only_managed_titles() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /v1/vaults/vault1/items HTTP", 200, "[{\"id\":\"old-id\",\"title\":\"OLD\"}]"),
            ("POST /v1/vaults/vault1/items", 200, "{}"),
            ("DELETE /v1/vaults/vault1/items/old-id", 204, ""),
        ]));
        let config = json!({"connect_url":base,"token":"op_token","vault_id":"vault1","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = onepassword_sync(&config, &secrets, &["OLD".to_string()]).await.expect("1password sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/items")).expect("create item");
        let body: Value = serde_json::from_str(&create.3).expect("json body");
        assert_eq!(body["title"], "API_KEY");
        assert_eq!(body["fields"][0]["label"], "value");
        assert_eq!(body["fields"][0]["value"], "v1");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/items/old-id")), "mirror should delete the previously managed item");
    }

    #[tokio::test]
    async fn onepassword_updates_the_configured_field_on_an_existing_item() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /v1/vaults/vault1/items HTTP", 200, "[{\"id\":\"item-1\",\"title\":\"API_KEY\"}]"),
            ("GET /v1/vaults/vault1/items/item-1", 200, "{\"id\":\"item-1\",\"title\":\"API_KEY\",\"category\":\"API_CREDENTIAL\",\"fields\":[{\"label\":\"value\",\"value\":\"old\",\"type\":\"CONCEALED\"}]}"),
            ("PUT /v1/vaults/vault1/items/item-1", 200, "{}"),
        ]));
        let config = json!({"connect_url":base,"token":"op_token","vault_id":"vault1"});
        let secrets = vec![("API_KEY".to_string(), "new".to_string())];
        let (report, _) = onepassword_sync(&config, &secrets, &[]).await.expect("1password sync");
        assert!(report.contains("updated=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, _, _, _)| m == "PUT").expect("put item");
        let body: Value = serde_json::from_str(&put.3).expect("json body");
        assert_eq!(body["fields"][0]["value"], "new");
    }

    #[tokio::test]
    async fn dokploy_merges_the_application_env_and_mirrors_managed_keys() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("application.one", 200, "{\"env\":\"OLD=1\\nKEEP=2\\n\",\"buildArgs\":\"\",\"buildSecrets\":\"\",\"createEnvFile\":true}"),
            ("saveEnvironment", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"api_key":"dok_key","application_id":"app1","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = dokploy_sync(&config, &secrets, &["OLD".to_string()]).await.expect("dokploy sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let save = calls.iter().find(|(_, p, _, _)| p.ends_with("/api/application.saveEnvironment")).expect("save call");
        let body: Value = serde_json::from_str(&save.3).expect("json body");
        let env = body["env"].as_str().expect("env string");
        assert!(env.contains("API_KEY=v1"), "{}", env);
        assert!(env.contains("KEEP=2"), "{}", env);
        assert!(!env.contains("OLD=1"), "{}", env);
    }

    #[tokio::test]
    async fn caprover_logs_in_and_updates_app_env_vars() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("POST /api/v2/login", 200, "{\"status\":100,\"data\":{\"token\":\"cap_token\"}}"),
            ("GET /api/v2/user/apps/appDefinitions HTTP", 200, "{\"status\":100,\"data\":{\"appDefinitions\":[{\"appName\":\"app\",\"envVars\":[{\"key\":\"OLD\",\"value\":\"1\"}]}]}}"),
            ("POST /api/v2/user/apps/appDefinitions/update/", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"password":"captain42","app_name":"app","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = caprover_sync(&config, &secrets, &["OLD".to_string()]).await.expect("caprover sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let update = calls.iter().find(|(_, p, _, _)| p.ends_with("/appDefinitions/update/")).expect("update call");
        let body: Value = serde_json::from_str(&update.3).expect("json body");
        let envs = body["envVars"].as_array().expect("envVars");
        assert!(envs.iter().any(|v| v["key"] == "API_KEY" && v["value"] == "v1"));
        assert!(!envs.iter().any(|v| v["key"] == "OLD"));
    }

    #[tokio::test]
    async fn portainer_updates_stack_env_and_keeps_the_stack_file() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/stacks HTTP", 200, "[{\"Id\":1,\"Name\":\"web\",\"EndpointId\":2}]"),
            ("GET /api/stacks/1 HTTP", 200, "{\"Id\":1,\"Name\":\"web\",\"EndpointId\":2,\"Env\":[{\"name\":\"OLD\",\"value\":\"1\"},{\"name\":\"KEEP\",\"value\":\"2\"}]}"),
            ("GET /api/stacks/1/file", 200, "{\"StackFileContent\":\"services: {}\"}"),
            ("PUT /api/stacks/1", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"api_key":"pt_key","stack_id":1,"mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = portainer_sync(&config, &secrets, &["OLD".to_string()]).await.expect("portainer sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, p, _, _)| m == "PUT" && p.starts_with("/api/stacks/1?")).expect("update call");
        assert!(put.1.contains("endpointId=2"), "{}", put.1);
        let body: Value = serde_json::from_str(&put.3).expect("json body");
        assert_eq!(body["StackFileContent"], "services: {}");
        let envs = body["Env"].as_array().expect("env");
        assert!(envs.iter().any(|v| v["name"] == "API_KEY" && v["value"] == "v1"));
        assert!(envs.iter().any(|v| v["name"] == "KEEP"));
        assert!(!envs.iter().any(|v| v["name"] == "OLD"));
    }

    #[tokio::test]
    async fn docker_swarm_recreates_immutable_secrets_and_prunes() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /v1.47/secrets HTTP", 200, "[{\"ID\":\"old-id\",\"Spec\":{\"Name\":\"OLD\"}}]"),
            ("POST /v1.47/secrets/create", 201, "{\"ID\":\"new-id\"}"),
            ("DELETE /v1.47/secrets/old-id", 204, ""),
        ]));
        let config = json!({"api_url":base,"mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = docker_swarm_sync(&config, &secrets, &["OLD".to_string()]).await.expect("docker sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/secrets/create")).expect("create call");
        let body: Value = serde_json::from_str(&create.3).expect("json body");
        assert_eq!(body["Name"], "API_KEY");
        assert_eq!(openwarp_crypto::unb64(body["Data"].as_str().expect("data")).expect("base64"), b"v1");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/secrets/old-id")), "mirror should delete the previously managed secret");
    }

    #[test]
    fn name_template_uses_the_environment_and_secret_key() {
        let config = json!({"_environment": "production", "name_template": "{{environment}}/{{secretKey}}"});
        let secrets = vec![("api_key".to_string(), "v1".to_string())];
        assert_eq!(trigger_desired(&config, &secrets), vec![("production/api_key".to_string(), "v1".to_string())]);
        let prefixed = json!({"_environment": "staging", "prefix": "{{environment}}/"});
        assert_eq!(trigger_desired(&prefixed, &secrets), vec![("staging/api_key".to_string(), "v1".to_string())]);
        let suffixed = json!({"_environment": "staging", "suffix": "_{{environment}}"});
        assert_eq!(trigger_desired(&suffixed, &secrets), vec![("api_key_staging".to_string(), "v1".to_string())]);
    }

    #[test]
    fn naming_is_off_unless_configured_and_templates_win() {
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        assert_eq!(trigger_desired(&json!({}), &secrets), secrets);
        let both = json!({"prefix": "APP_", "suffix": "_V2", "name_template": "{{secretKey}}__{{environment}}"});
        assert_eq!(desired_name(&both, "API_KEY"), "API_KEY__");
    }

    #[test]
    fn local_name_reverses_prefix_suffix_and_template() {
        let prefixed = json!({"_environment": "prod", "prefix": "APP_", "suffix": "_{{environment}}"});
        assert_eq!(desired_name(&prefixed, "KEY"), "APP_KEY_prod");
        assert_eq!(local_name(&prefixed, "APP_KEY_prod"), "KEY");
        assert_eq!(local_name(&prefixed, "UNRELATED"), "UNRELATED");
        let templated = json!({"_environment": "prod", "name_template": "{{environment}}/{{secretKey}}"});
        assert_eq!(local_name(&templated, "prod/KEY"), "KEY");
        let ssm = json!({"path_prefix": "/app/prod", "prefix": "APP_"});
        assert_eq!(local_name(&ssm, "/app/prod/APP_KEY"), "KEY");
    }

    #[test]
    fn case_rewrites_the_key_before_wrapping() {
        let terraform = json!({"prefix": "TF_VAR_", "case": "upper"});
        assert_eq!(desired_name(&terraform, "db_host"), "TF_VAR_DB_HOST");
        assert_eq!(desired_name(&json!({"prefix": "app_", "suffix": "_v1", "case": "lower"}), "API_KEY"), "app_api_key_v1");
        assert_eq!(desired_name(&json!({"name_template": "{{environment}}_{{secretKey}}", "_environment": "Prod", "case": "lower"}), "API_KEY"), "Prod_api_key");
        assert_eq!(desired_name(&json!({"case": "upper"}), "mixedCase"), "MIXEDCASE");
        assert_eq!(local_name(&terraform, "TF_VAR_DB_HOST"), "DB_HOST");
    }

    #[test]
    fn name_template_needs_exactly_one_secret_key_placeholder() {
        assert!(validate_naming(&json!({"name_template": "{{secretKey}}"})).is_ok());
        assert!(validate_naming(&json!({})).is_ok());
        assert!(validate_naming(&json!({"name_template": "static"})).is_err());
        assert!(validate_naming(&json!({"name_template": "{{secretKey}}_{{secretKey}}"})).is_err());
        assert!(validate_naming(&json!({"case": "upper"})).is_ok());
        assert!(validate_naming(&json!({"case": "title"})).is_err());
    }

    #[tokio::test]
    async fn aws_secrets_manager_assumes_a_role_before_signing() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("Action=AssumeRole", 200, "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"),
            ("secretsmanager.ListSecrets", 200, "{\"SecretList\":[]}"),
            ("secretsmanager.PutSecretValue", 200, "{}"),
        ]));
        let config = json!({"region":"us-east-1","access_key_id":"BASE","secret_access_key":"base-secret","role_arn":"arn:aws:iam::123456789012:role/openwarp","endpoint":base,"sts_endpoint":base,"mapping":"one_to_one"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        aws_secrets_manager_sync(&config, &secrets, &[]).await.expect("aws sm sync");
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(_, _, head, _)| head.contains("secretsmanager.PutSecretValue")).expect("put call");
        assert!(put.2.contains("Credential=ASIAEXAMPLE/"), "{}", put.2);
        assert!(put.2.to_lowercase().contains("x-amz-security-token: role-token"), "{}", put.2);
    }

    #[tokio::test]
    async fn pull_reads_aws_secrets_manager_values_and_strips_the_prefix() {
        let (base, _calls) = start_mock_routes(mock_routes(&[
            ("secretsmanager.ListSecrets", 200, "{\"SecretList\":[{\"Name\":\"app/API_KEY\"}]}"),
            ("secretsmanager.GetSecretValue", 200, "{\"SecretString\":\"v1\"}"),
        ]));
        let config = json!({"region":"us-east-1","access_key_id":"AKIA","secret_access_key":"secret","endpoint":base,"mapping":"one_to_one","prefix":"app/"});
        let values = pull("aws_secrets_manager", &config).await.expect("pull");
        assert_eq!(values, vec![("API_KEY".to_string(), "v1".to_string())]);
    }

    #[tokio::test]
    async fn pull_strips_a_configured_suffix() {
        let (base, _calls) = start_mock_routes(mock_routes(&[
            ("secretsmanager.ListSecrets", 200, "{\"SecretList\":[{\"Name\":\"APP_API_KEY_prod\"}]}"),
            ("secretsmanager.GetSecretValue", 200, "{\"SecretString\":\"v1\"}"),
        ]));
        let config = json!({"region":"us-east-1","access_key_id":"AKIA","secret_access_key":"secret","endpoint":base,"mapping":"one_to_one","prefix":"APP_","suffix":"_{{environment}}","_environment":"prod"});
        let values = pull("aws_secrets_manager", &config).await.expect("pull");
        assert_eq!(values, vec![("API_KEY".to_string(), "v1".to_string())]);
    }

    #[tokio::test]
    async fn pull_reads_1password_field_values() {
        let (base, _calls) = start_mock_routes(mock_routes(&[
            ("GET /v1/vaults/vault1/items HTTP", 200, "[{\"id\":\"item-1\",\"title\":\"API_KEY\"}]"),
            ("GET /v1/vaults/vault1/items/item-1", 200, "{\"id\":\"item-1\",\"title\":\"API_KEY\",\"fields\":[{\"label\":\"value\",\"value\":\"v1\"}]}"),
        ]));
        let config = json!({"connect_url":base,"token":"op_token","vault_id":"vault1"});
        let values = pull("1password", &config).await.expect("pull");
        assert_eq!(values, vec![("API_KEY".to_string(), "v1".to_string())]);
    }

    #[tokio::test]
    async fn bitbucket_creates_and_mirrors() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /2.0/repositories/ws/repo/pipelines_config/variables/", 200, "{\"values\":[{\"uuid\":\"old-id\",\"key\":\"OLD\",\"value\":\"1\"}]}"),
            ("POST /2.0/repositories/ws/repo/pipelines_config/variables/", 200, "{}"),
            ("DELETE /2.0/repositories/ws/repo/pipelines_config/variables/old-id", 204, ""),
        ]));
        let config = json!({"base_url":format!("{}/2.0", base),"workspace":"ws","repo_slug":"repo","token":"tok","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, managed) = bitbucket_sync(&config, &secrets, &["OLD".to_string()]).await.expect("bitbucket sync");
        assert!(report.contains("created=1"), "{}", report);
        assert_eq!(managed, vec!["API_KEY".to_string()]);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.contains("/pipelines_config/variables/")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["key"], "API_KEY");
        assert_eq!(body["secured"], true);
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/variables/old-id")));
    }

    #[tokio::test]
    async fn circleci_recreates_existing_variables() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /project/gh/org/repo/envvar", 200, "{\"items\":[{\"name\":\"API_KEY\",\"value\":\"old\"}]}"),
            ("DELETE /project/gh/org/repo/envvar/API_KEY", 204, ""),
            ("POST /project/gh/org/repo/envvar", 201, "{}"),
        ]));
        let config = json!({"base_url":base,"project_slug":"gh/org/repo","token":"tok"});
        let secrets = vec![("API_KEY".to_string(), "new".to_string())];
        let (report, _) = circleci_sync(&config, &secrets, &[]).await.expect("circleci sync");
        assert!(report.contains("updated=1"), "{}", report);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/envvar/API_KEY")));
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/envvar")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["value"], "new");
    }

    #[tokio::test]
    async fn teamcity_updates_a_parameter() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /app/rest/projects/_Root/parameters", 200, "{\"property\":[{\"name\":\"API_KEY\",\"value\":\"old\"}]}"),
            ("PUT /app/rest/projects/_Root/parameters/API_KEY", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"token":"tok"});
        let secrets = vec![("API_KEY".to_string(), "new".to_string())];
        let (report, _) = teamcity_sync(&config, &secrets, &[]).await.expect("teamcity sync");
        assert!(report.contains("updated=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, p, _, _)| m == "PUT" && p.ends_with("/parameters/API_KEY")).expect("update");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        assert_eq!(body["value"], "new");
    }

    #[tokio::test]
    async fn travisci_creates_an_environment_variable() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /repo/owner%2Frepo/env_vars", 200, "{\"env_vars\":[]}"),
            ("POST /repo/owner%2Frepo/env_vars", 201, "{}"),
        ]));
        let config = json!({"base_url":base,"repo":"owner/repo","token":"tok"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = travisci_sync(&config, &secrets, &[]).await.expect("travis sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/env_vars")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["env_var"]["name"], "API_KEY");
        assert_eq!(body["env_var"]["public"], false);
    }

    #[tokio::test]
    async fn terraform_cloud_creates_a_variable() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/v2/workspaces/ws-1/vars", 200, "{\"data\":[]}"),
            ("POST /api/v2/workspaces/ws-1/vars", 201, "{}"),
        ]));
        let config = json!({"base_url":format!("{}/api/v2", base),"token":"tok","workspace_id":"ws-1"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = terraform_cloud_sync(&config, &secrets, &[]).await.expect("tf cloud sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/vars")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["data"]["attributes"]["key"], "API_KEY");
        assert_eq!(body["data"]["attributes"]["sensitive"], true);
    }

    #[tokio::test]
    async fn qovery_creates_a_variable() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /organization/org/project/proj/environment/env/variable", 200, "{\"results\":[]}"),
            ("POST /organization/org/project/proj/environment/env/variable", 201, "{}"),
        ]));
        let config = json!({"base_url":base,"token":"tok","organization_id":"org","project_id":"proj","environment_id":"env"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = qovery_sync(&config, &secrets, &[]).await.expect("qovery sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/variable")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["key"], "API_KEY");
        assert_eq!(body["scope"], "ENV");
    }

    #[tokio::test]
    async fn laravel_forge_merges_the_environment_file() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/orgs/org/servers/1/sites/1/environment", 200, "{\"data\":{\"attributes\":{\"content\":\"OLD=1\\nKEEP=2\\n\"}}}"),
            ("PUT /api/orgs/org/servers/1/sites/1/environment", 202, "{}"),
        ]));
        let config = json!({"base_url":format!("{}/api", base),"token":"tok","organization":"org","server_id":1,"site_id":1,"mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = laravel_forge_sync(&config, &secrets, &["OLD".to_string()]).await.expect("forge sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, _, _, _)| m == "PUT").expect("update");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        let env = body["environment"].as_str().expect("environment");
        assert!(env.contains("API_KEY=v1"), "{}", env);
        assert!(env.contains("KEEP=2"), "{}", env);
        assert!(!env.contains("OLD=1"), "{}", env);
    }

    #[tokio::test]
    async fn openwarp_pushes_and_mirrors_the_remote_environment() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/envs/env1/secrets", 200, "{\"secrets\":[{\"id\":\"s1\",\"key\":\"OLD\",\"value\":\"1\"}],\"total\":1}"),
            ("PUT /api/envs/env1/secrets", 200, "{}"),
            ("DELETE /api/secrets/s1", 204, ""),
        ]));
        let config = json!({"base_url":base,"token":"tok","env_id":"env1","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = openwarp_sync(&config, &secrets, &["OLD".to_string()]).await.expect("openwarp sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, p, _, _)| m == "PUT" && p.ends_with("/secrets")).expect("deploy");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        assert_eq!(body["secrets"][0]["key"], "API_KEY");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/api/secrets/s1")));
    }

    #[tokio::test]
    async fn devin_recreates_existing_org_secrets() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /v3/organizations/org-1/secrets", 200, "{\"items\":[{\"key\":\"OLD\",\"secret_id\":\"secret-1\",\"secret_type\":\"key-value\"}],\"has_next_page\":false}"),
            ("DELETE /v3/organizations/org-1/secrets/secret-1", 204, ""),
            ("POST /v3/organizations/org-1/secrets", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"token":"cog_test","org_id":"org-1","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = devin_sync(&config, &secrets, &["OLD".to_string()]).await.expect("devin sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/secrets")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["key"], "API_KEY");
        assert_eq!(body["type"], "key-value");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/secret-1")));
    }

    #[tokio::test]
    async fn cloudflare_secrets_store_recreates_write_only_values() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /client/v4/accounts/acc/secrets_store/stores/store/secrets", 200, "{\"result\":[{\"id\":\"old-id\",\"name\":\"OLD\",\"status\":\"active\"}],\"result_info\":{\"total_pages\":1}}"),
            ("DELETE /client/v4/accounts/acc/secrets_store/stores/store/secrets/old-id", 204, ""),
            ("POST /client/v4/accounts/acc/secrets_store/stores/store/secrets", 200, "{}"),
        ]));
        let config = json!({"base_url":format!("{}/client/v4", base),"token":"cf_token","account_id":"acc","store_id":"store","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = cloudflare_secrets_store_sync(&config, &secrets, &["OLD".to_string()]).await.expect("cf store sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/secrets")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body[0]["name"], "API_KEY");
        assert_eq!(body[0]["scopes"][0], "workers");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/secrets/old-id")));
    }

    #[tokio::test]
    async fn octopus_deploy_updates_the_variable_collection() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/Spaces-1/projects/Projects-1/variables", 200, "{\"Variables\":[{\"Name\":\"OLD\",\"Value\":\"1\"},{\"Name\":\"KEEP\",\"Value\":\"2\"}]}"),
            ("PUT /api/Spaces-1/projects/Projects-1/variables", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"api_key":"API-TEST","project_id":"Projects-1","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = octopus_deploy_sync(&config, &secrets, &["OLD".to_string()]).await.expect("octopus sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, _, _, _)| m == "PUT").expect("update");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        let vars = body["Variables"].as_array().expect("variables");
        assert!(vars.iter().any(|v| v["Name"] == "API_KEY" && v["Value"] == "v1"));
        assert!(vars.iter().any(|v| v["Name"] == "KEEP"));
        assert!(!vars.iter().any(|v| v["Name"] == "OLD"));
    }

    #[tokio::test]
    async fn azure_devops_updates_the_variable_group() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /project/_apis/distributedtask/variablegroups/1", 200, "{\"variables\":{\"OLD\":{\"value\":\"1\"},\"KEEP\":{\"value\":\"2\"}}}"),
            ("PUT /project/_apis/distributedtask/variablegroups/1", 200, "{}"),
        ]));
        let config = json!({"base_url":base,"organization":"org","project":"project","group_id":"1","token":"pat","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = azure_devops_sync(&config, &secrets, &["OLD".to_string()]).await.expect("azure devops sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, _, _, _)| m == "PUT").expect("update");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        assert_eq!(body["variables"]["API_KEY"]["value"], "v1");
        assert_eq!(body["variables"]["KEEP"]["value"], "2");
        assert!(body["variables"].get("OLD").is_none());
    }

    #[tokio::test]
    async fn cursor_sets_team_secrets_and_prunes_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /v1/team/secrets?limit=100", 200, "{\"items\":[{\"id\":\"v1\",\"name\":\"OLD\",\"type\":\"runtime_secret\"}]}"),
            ("PUT /v1/team/secrets/API_KEY", 200, "{}"),
            ("DELETE /v1/team/secrets/OLD", 204, ""),
        ]));
        let config = json!({"base_url":base,"token":"cur_test","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = cursor_sync(&config, &secrets, &["OLD".to_string()]).await.expect("cursor sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, p, _, _)| m == "PUT" && p.ends_with("/secrets/API_KEY")).expect("set secret");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        assert_eq!(body["value"], "v1");
        assert_eq!(body["type"], "runtime_secret");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/secrets/OLD")));
    }

    #[tokio::test]
    async fn northflank_merges_secret_group_variables() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /v1/projects/proj/secrets/group/details", 200, "{\"data\":{\"secrets\":{\"variables\":{\"OLD\":\"1\",\"KEEP\":\"2\"}}}}"),
            ("PATCH /v1/projects/proj/secrets/group", 200, "{}"),
        ]));
        let config = json!({"base_url":format!("{}/v1", base),"token":"nf_token","project_id":"proj","secret_group_id":"group","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = northflank_sync(&config, &secrets, &["OLD".to_string()]).await.expect("northflank sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let patch = calls.iter().find(|(m, _, _, _)| m == "PATCH").expect("patch");
        let body: Value = serde_json::from_str(&patch.3).expect("json");
        assert_eq!(body["secrets"]["variables"]["API_KEY"], "v1");
        assert_eq!(body["secrets"]["variables"]["KEEP"], "2");
        assert!(body["secrets"]["variables"].get("OLD").is_none());
    }

    #[tokio::test]
    async fn spacelift_adds_and_deletes_stack_config() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("\"id\":\"OLD\"", 200, "{\"data\":{\"stack\":{\"configElement\":{\"id\":\"OLD\",\"type\":\"ENVIRONMENT_VARIABLE\",\"value\":\"1\",\"writeOnly\":false}}}}"),
            ("configElement", 200, "{\"data\":{\"stack\":{\"configElement\":null}}}"),
            ("stackConfigAdd", 200, "{\"data\":{\"stackConfigAdd\":{\"id\":\"API_KEY\"}}}"),
            ("stackConfigDelete", 200, "{\"data\":{\"stackConfigDelete\":{\"id\":\"OLD\"}}}"),
        ]));
        let config = json!({"base_url":format!("{}/graphql", base),"token":"spacelift_token","stack_id":"stack-1","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = spacelift_sync(&config, &secrets, &["OLD".to_string()]).await.expect("spacelift sync");
        assert!(report.contains("created=1"), "{}", report);
        assert!(report.contains("deleted=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let add = calls.iter().find(|(_, _, _, body)| body.contains("stackConfigAdd")).expect("add");
        assert!(add.3.contains("\"value\":\"v1\""), "{}", add.3);
        assert!(calls.iter().any(|(_, _, _, body)| body.contains("stackConfigDelete") && body.contains("\"id\":\"OLD\"")), "mirror should delete the managed config");
    }

    #[tokio::test]
    async fn rundeck_creates_keys_and_prunes_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/19/storage/keys/project/proj HTTP", 200, "{\"resources\":[{\"type\":\"file\",\"name\":\"OLD\"}]}"),
            ("POST /api/19/storage/keys/project/proj/API_KEY", 200, "{}"),
            ("DELETE /api/19/storage/keys/project/proj/OLD", 204, ""),
        ]));
        let config = json!({"instance_url":base,"api_token":"rd_token","project":"proj","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = rundeck_sync(&config, &secrets, &["OLD".to_string()]).await.expect("rundeck sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/API_KEY")).expect("create");
        assert_eq!(post.3, "v1");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/OLD")));
    }

    #[tokio::test]
    async fn cloud66_creates_env_vars_and_prunes_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /3/stacks/stack/environments?page=1&per_page=100", 200, "{\"response\":[{\"key\":\"OLD\",\"value\":\"1\",\"readonly\":false,\"is_generated\":false}],\"pagination\":{\"next\":null}}"),
            ("POST /3/stacks/stack/environments", 200, "{}"),
            ("DELETE /3/stacks/stack/environments/OLD", 204, ""),
        ]));
        let config = json!({"base_url":base,"access_token":"c66_token","stack_id":"stack","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = cloud66_sync(&config, &secrets, &["OLD".to_string()]).await.expect("cloud66 sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/environments")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["key"], "API_KEY");
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/environments/OLD")));
    }

    #[tokio::test]
    async fn humanitec_creates_values_and_prunes_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /orgs/org/apps/app/values", 200, "[{\"key\":\"OLD\",\"value\":\"1\",\"source\":\"app\"},{\"key\":\"KEEP\",\"value\":\"2\",\"source\":\"app\"}]"),
            ("POST /orgs/org/apps/app/values", 200, "{}"),
            ("DELETE /orgs/org/apps/app/values/OLD", 204, ""),
        ]));
        let config = json!({"base_url":base,"api_token":"hm_token","org":"org","app":"app","scope":"application","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = humanitec_sync(&config, &secrets, &["OLD".to_string()]).await.expect("humanitec sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/values")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["key"], "API_KEY");
        assert_eq!(body["is_secret"], true);
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/values/OLD")));
    }

    #[tokio::test]
    async fn ovh_kms_creates_a_bundle_when_none_exists() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/okms/v2/secret/app?includeData=true", 404, "{}"),
            ("POST /api/okms/v2/secret", 200, "{}"),
        ]));
        let config = json!({"okms_domain":base,"okms_id":"okms","token":"ovh_token","path":"app"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = ovh_kms_sync(&config, &secrets, &[]).await.expect("ovh sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/v2/secret")).expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["path"], "app");
        assert_eq!(body["version"]["data"]["API_KEY"], "v1");
    }

    #[tokio::test]
    async fn keeper_creates_login_records_and_prunes_managed_titles() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("sync-down", 200, "{}"),
            ("ls --format=json", 200, "{\"records\":[{\"uid\":\"uid1\",\"type\":\"record\"}]}"),
            ("get --format=json uid1", 200, "{\"type\":\"login\",\"title\":\"OLD\",\"fields\":[{\"type\":\"password\",\"value\":[\"1\"]}]}"),
            ("record-add", 200, "{}"),
            ("rm -f --purge", 200, "{}"),
        ]));
        let config = json!({"instance_url":base,"api_key":"keeper_key","folder_uid":"folder","mode":"mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = keeper_sync(&config, &secrets, &["OLD".to_string()]).await.expect("keeper sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let add = calls.iter().find(|(_, _, _, body)| body.contains("record-add")).expect("create");
        assert!(add.3.contains("API_KEY"), "{}", add.3);
        assert!(add.3.contains("$BASE64:djE="), "{}", add.3);
        assert!(calls.iter().any(|(_, _, _, body)| body.contains("rm -f --purge uid1")));
    }

    #[tokio::test]
    async fn oci_vault_creates_a_secret_with_a_signed_request() {
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa key");
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).expect("pem").to_string();
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /20180608/secrets?compartmentId=comp&vaultId=vault", 200, "{\"items\":[]}"),
            ("POST /20180608/secrets", 200, "{\"id\":\"secret-1\"}"),
        ]));
        let config = json!({"endpoint":base,"tenancy_ocid":"tenancy","user_ocid":"user","fingerprint":"fp","private_key":pem,"region":"us-ashburn-1","compartment_id":"comp","vault_id":"vault","key_id":"key"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = oci_vault_sync(&config, &secrets, &[]).await.expect("oci sync");
        assert!(report.contains("created=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/20180608/secrets").expect("create");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["secretName"], "API_KEY");
        assert_eq!(body["secretContent"]["content"], openwarp_crypto::b64(b"v1"));
        assert!(post.2.to_lowercase().contains("authorization: signature version=\"1\""), "{}", post.2);
    }

    #[tokio::test]
    async fn huggingface_space_sync_upserts_and_prunes_only_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /api/spaces/acme/app/secrets", 200, r#"{"KEEP":{"key":"KEEP","updatedAt":"2026-01-01T00:00:00.000Z"},"OLD":{"key":"OLD","updatedAt":"2026-01-01T00:00:00.000Z"}}"#),
            ("POST /api/spaces/acme/app/secrets", 200, "{}"),
            ("DELETE /api/spaces/acme/app/secrets", 200, "{}"),
        ]));
        let config = json!({"token": "hf_admin", "namespace": "acme", "repo": "app", "base_url": base, "mode": "mirror"});
        let secrets = vec![("KEEP".to_string(), "v1".to_string()), ("NEW_KEY".to_string(), "v2".to_string())];
        let (report, managed) = huggingface_sync(&config, &secrets, &["OLD".to_string()]).await.expect("sync");
        assert!(report.contains("created=1") && report.contains("updated=1") && report.contains("deleted=1"), "{}", report);
        assert_eq!(managed, vec!["KEEP".to_string(), "NEW_KEY".to_string()]);
        let calls = calls.lock().unwrap().clone();
        assert!(calls.iter().any(|(m, _, _, b)| m == "DELETE" && b.contains("\"key\":\"OLD\"")));
        assert!(!calls.iter().any(|(m, _, _, b)| m == "DELETE" && b.contains("NEW_KEY")));
        let err = huggingface_sync(&json!({"token":"hf","namespace":"acme","repo":"app","base_url":base}), &[("bad-name".into(), "v".into())], &[]).await.unwrap_err();
        assert!(err.contains("[A-Za-z]"), "{}", err);
    }

    #[tokio::test]
    async fn huggingface_variables_skip_an_unchanged_value() {
        let (base, _) = start_mock_routes(mock_routes(&[
            ("GET /api/spaces/acme/app/variables", 200, r#"{"KEEP":{"key":"KEEP","value":"same","updatedAt":"2026-01-01T00:00:00.000Z"}}"#),
            ("POST /api/spaces/acme/app/variables", 200, "{}"),
        ]));
        let config = json!({"token": "hf_admin", "namespace": "acme", "repo": "app", "target": "variables", "base_url": base});
        let (report, _) = huggingface_sync(&config, &[("KEEP".into(), "same".into())], &[]).await.expect("sync");
        assert!(report.contains("unchanged=1"), "{}", report);
        let imported = pull("huggingface", &config).await.expect("import");
        assert_eq!(imported, vec![("KEEP".to_string(), "same".to_string())]);
    }

    #[tokio::test]
    async fn webhook_signs_the_body_with_the_log_stream_construction() {
        let (base, calls) = start_mock_routes(mock_routes(&[("POST /hook", 200, "{}")]));
        let config = json!({"url": format!("{}/hook", base), "token": "bearer-token", "signing_secret": "hook-secret"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let report = webhook_sync(&config, &secrets).await.expect("webhook sync");
        assert!(report.contains("signed"), "{}", report);
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, _, _, _)| m == "POST").expect("post");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["secrets"]["API_KEY"], "v1");
        let headers = post.2.to_lowercase();
        assert!(headers.contains("authorization: bearer bearer-token"), "{}", post.2);
        let timestamp = headers.lines().find_map(|l| l.strip_prefix("x-openwarp-timestamp:")).expect("timestamp header").trim();
        let signature = headers.lines().find_map(|l| l.strip_prefix("x-openwarp-signature:")).expect("signature header").trim();
        assert_eq!(signature, webhook_signature("hook-secret", timestamp.parse().unwrap(), &post.3));
    }

    #[tokio::test]
    async fn sync_applies_naming_to_adapters_without_a_managed_name_list() {
        let (base, calls) = start_mock_routes(mock_routes(&[("POST /hook", 200, "{}")]));
        let config = json!({"url": format!("{}/hook", base), "prefix": "APP_", "suffix": "_V1"});
        sync("webhook", &config, &[("API_KEY".to_string(), "v1".to_string())]).await.expect("webhook sync");
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, _, _, _)| m == "POST").expect("post");
        let body: Value = serde_json::from_str(&post.3).expect("json");
        assert_eq!(body["secrets"]["APP_API_KEY_V1"], "v1");
    }

    #[tokio::test]
    async fn sync_refuses_a_template_that_collapses_every_key() {
        let (base, calls) = start_mock_routes(mock_routes(&[("POST /hook", 200, "{}")]));
        let config = json!({"url": format!("{}/hook", base), "name_template": "STATIC"});
        let err = sync("webhook", &config, &[("API_KEY".to_string(), "v1".to_string())]).await.expect_err("template rejected");
        assert!(err.contains("name_template"), "{}", err);
        assert!(calls.lock().unwrap().is_empty(), "nothing should be posted");
    }

    #[tokio::test]
    async fn webhook_without_a_signing_secret_stays_unsigned() {
        let (base, calls) = start_mock_routes(mock_routes(&[("POST /hook", 200, "{}")]));
        let config = json!({"url": format!("{}/hook", base), "token": "bearer-token"});
        webhook_sync(&config, &[("API_KEY".to_string(), "v1".to_string())]).await.expect("webhook sync");
        let calls = calls.lock().unwrap();
        let post = calls.iter().find(|(m, _, _, _)| m == "POST").expect("post");
        assert!(!post.2.to_lowercase().contains("x-openwarp-signature"), "no signature without a secret: {}", post.2);
    }

    #[tokio::test]
    async fn scaleway_creates_a_secret_and_version_and_prunes_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /secret-manager/v1beta1/regions/fr-par/secrets?", 200, "{\"secrets\":[{\"id\":\"sec-old\",\"name\":\"OLD\"}],\"total_count\":1}"),
            ("POST /secret-manager/v1beta1/regions/fr-par/secrets HTTP", 200, "{\"id\":\"sec-new\",\"name\":\"API_KEY\"}"),
            ("POST /secret-manager/v1beta1/regions/fr-par/secrets/sec-new/versions", 200, "{\"revision\":\"1\"}"),
            ("DELETE /secret-manager/v1beta1/regions/fr-par/secrets/sec-old", 204, ""),
        ]));
        let config = json!({"base_url": base, "region": "fr-par", "secret_key": "scw_key", "project_id": "proj", "mode": "mirror"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (report, _) = scaleway_sync(&config, &secrets, &["OLD".to_string()]).await.expect("scaleway sync");
        assert!(report.contains("created=1"), "{}", report);
        assert!(report.contains("deleted=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(m, p, _, _)| m == "POST" && p.split('?').next() == Some("/secret-manager/v1beta1/regions/fr-par/secrets")).expect("create");
        let body: Value = serde_json::from_str(&create.3).expect("json");
        assert_eq!(body["name"], "API_KEY");
        assert_eq!(body["project_id"], "proj");
        assert_eq!(body["type"], "opaque");
        let version = calls.iter().find(|(m, p, _, _)| m == "POST" && p.ends_with("/versions")).expect("version");
        let version_body: Value = serde_json::from_str(&version.3).expect("json");
        assert_eq!(version_body["data"], openwarp_crypto::b64(b"v1"));
        assert!(calls.iter().any(|(m, _, h, _)| m == "GET" && h.to_lowercase().contains("x-auth-token: scw_key")));
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.ends_with("/secrets/sec-old")));
    }

    #[tokio::test]
    async fn scaleway_unchanged_value_adds_no_version() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /secret-manager/v1beta1/regions/fr-par/secrets?", 200, "{\"secrets\":[{\"id\":\"sec-1\",\"name\":\"API_KEY\"}],\"total_count\":1}"),
            ("GET /secret-manager/v1beta1/regions/fr-par/secrets/sec-1/versions/latest/access", 200, &format!("{{\"data\":\"{}\"}}", openwarp_crypto::b64(b"v1"))),
        ]));
        let config = json!({"base_url": base, "region": "fr-par", "secret_key": "scw_key", "project_id": "proj"});
        let (report, _) = scaleway_sync(&config, &[("API_KEY".to_string(), "v1".to_string())], &[]).await.expect("scaleway sync");
        assert!(report.contains("unchanged=1"), "{}", report);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|(m, _, _, _)| m == "GET"), "an unchanged value must not write: {:?}", calls.iter().map(|(m, p, _, _)| format!("{} {}", m, p)).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn azure_app_configuration_sets_a_key_and_prunes_managed_names() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("GET /kv?key=*&label=%00&api-version=1.0", 200, "{\"items\":[{\"key\":\"OLD\",\"value\":\"1\"}]}"),
            ("PUT /kv/API_KEY?api-version=1.0", 200, "{\"key\":\"API_KEY\",\"value\":\"v1\"}"),
            ("DELETE /kv/OLD?api-version=1.0", 200, "{\"key\":\"OLD\"}"),
        ]));
        let key_id = format!("id-{}", "appconfig"); let key_secret = format!("secret-{}", "appconfig");
        let config = json!({"endpoint": base, "id": key_id, "secret": openwarp_crypto::b64(key_secret.as_bytes()), "mode": "mirror"});
        let (report, _) = azure_app_configuration_sync(&config, &[("API_KEY".to_string(), "v1".to_string())], &["OLD".to_string()]).await.expect("appconfig sync");
        assert!(report.contains("created=1"), "{}", report);
        assert!(report.contains("deleted=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let put = calls.iter().find(|(m, _, _, _)| m == "PUT").expect("put");
        let body: Value = serde_json::from_str(&put.3).expect("json");
        assert_eq!(body["value"], "v1");
        let headers = &put.2;
        assert!(headers.to_lowercase().contains(&format!("authorization: hmac-sha256 credential={}&signedheaders=x-ms-date;host;x-ms-content-sha256&signature=", key_id)), "{}", headers);
        let date = headers.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("x-ms-date")).map(|(_, v)| v.trim().to_string())).expect("date");
        let content_hash = headers.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("x-ms-content-sha256")).map(|(_, v)| v.trim().to_string())).expect("hash");
        assert_eq!(content_hash, openwarp_crypto::b64(&Sha256::digest(put.3.as_bytes())));
        let parsed = reqwest::Url::parse(&base).unwrap();
        let host = match parsed.port() { Some(p) => format!("{}:{}", parsed.host_str().unwrap(), p), None => parsed.host_str().unwrap().to_string() };
        let to_sign = format!("PUT\n/kv/API_KEY?api-version=1.0\n{};{};{}", date, host, content_hash);
        let expected = openwarp_crypto::b64(&hmac(key_secret.as_bytes(), to_sign.as_bytes()));
        assert!(headers.contains(&format!("Signature={}", expected)), "signature mismatch: {}", headers);
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p.starts_with("/kv/OLD?")));
    }

    const PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYQJZ7VR/OW5fqVOvmn+BRt5SLWDPx2UVO3ALmn21ZE openwarp-test";
    const PUBKEY_NEW: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYQJZ7VR/OW5fqVOvmn+BRt5SLWDPx2UVO3ALmn21ZE replaced";

    #[tokio::test]
    async fn vultr_creates_and_patches_ssh_keys_and_prunes_managed_names() {
        let listed = format!("{{\"ssh_keys\":[{{\"id\":\"key-old\",\"name\":\"OLD\",\"ssh_key\":\"{}\"}},{{\"id\":\"key-1\",\"name\":\"DEPLOY\",\"ssh_key\":\"{}\"}}],\"meta\":{{\"links\":{{\"next\":\"\"}}}}}}", PUBKEY, PUBKEY);
        let (base, calls) = start_mock_routes(vec![
            ("GET /ssh-keys?per_page=100".into(), 200, listed),
            ("PATCH /ssh-keys/key-1".into(), 200, "{}".into()),
            ("POST /ssh-keys".into(), 201, "{\"ssh_key\":{\"id\":\"key-2\"}}".into()),
            ("DELETE /ssh-keys/key-old".into(), 204, String::new()),
        ]);
        let config = json!({"base_url": base, "api_key": "vultr-key", "mode": "mirror"});
        let secrets = vec![("DEPLOY".to_string(), PUBKEY_NEW.to_string()), ("BUILD".to_string(), PUBKEY.to_string())];
        let (report, _) = vultr_sync(&config, &secrets, &["OLD".to_string()]).await.expect("vultr sync");
        assert!(report.contains("created=1"), "{}", report);
        assert!(report.contains("updated=1"), "{}", report);
        assert!(report.contains("deleted=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let patch = calls.iter().find(|(m, _, _, _)| m == "PATCH").expect("patch");
        assert_eq!(serde_json::from_str::<Value>(&patch.3).unwrap()["ssh_key"], PUBKEY_NEW);
        let post = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/ssh-keys").expect("create");
        let body: Value = serde_json::from_str(&post.3).unwrap();
        assert_eq!(body["name"], "BUILD");
        assert_eq!(body["ssh_key"], PUBKEY);
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/ssh-keys/key-old"));
    }

    #[tokio::test]
    async fn vultr_rejects_a_value_that_is_not_a_public_key() {
        let (base, calls) = start_mock_routes(mock_routes(&[]));
        let config = json!({"base_url": base, "api_key": "vultr-key"});
        let err = vultr_sync(&config, &[("DEPLOY".to_string(), "not a key".to_string())], &[]).await.unwrap_err();
        assert!(err.contains("not an OpenSSH public key"), "{}", err);
        assert!(calls.lock().unwrap().is_empty(), "validation must fail before any request");
    }

    #[tokio::test]
    async fn hetzner_replaces_a_changed_key_and_prunes_managed_names() {
        let listed = format!("{{\"ssh_keys\":[{{\"id\":7,\"name\":\"OLD\",\"public_key\":\"{}\"}},{{\"id\":9,\"name\":\"DEPLOY\",\"public_key\":\"{}\"}}],\"meta\":{{\"pagination\":{{\"next_page\":null}}}}}}", PUBKEY, PUBKEY);
        let (base, calls) = start_mock_routes(vec![
            ("GET /ssh_keys?page=1&per_page=50".into(), 200, listed),
            ("DELETE /ssh_keys/9".into(), 204, String::new()),
            ("DELETE /ssh_keys/7".into(), 204, String::new()),
            ("POST /ssh_keys".into(), 201, "{\"ssh_key\":{\"id\":11}}".into()),
        ]);
        let config = json!({"base_url": base, "token": "hetzner-token", "mode": "mirror"});
        let (report, _) = hetzner_sync(&config, &[("DEPLOY".to_string(), PUBKEY_NEW.to_string())], &["OLD".to_string()]).await.expect("hetzner sync");
        assert!(report.contains("replaced=1"), "{}", report);
        assert!(report.contains("deleted=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let order: Vec<String> = calls.iter().map(|(m, p, _, _)| format!("{} {}", m, p)).collect();
        let replace_at = order.iter().position(|c| c == "DELETE /ssh_keys/9").expect("old key deleted");
        let create_at = order.iter().position(|c| c == "POST /ssh_keys").expect("new key created");
        assert!(replace_at < create_at, "the old key must be removed before the replacement: {:?}", order);
        let post = calls.iter().find(|(m, _, _, _)| m == "POST").unwrap();
        let body: Value = serde_json::from_str(&post.3).unwrap();
        assert_eq!(body["name"], "DEPLOY");
        assert_eq!(body["public_key"], PUBKEY_NEW);
        assert!(order.iter().any(|c| c == "DELETE /ssh_keys/7"), "mirror should remove the managed key");
    }

    #[tokio::test]
    async fn hetzner_unchanged_key_makes_no_writes() {
        let listed = format!("{{\"ssh_keys\":[{{\"id\":9,\"name\":\"DEPLOY\",\"public_key\":\"{}\"}}],\"meta\":{{\"pagination\":{{\"next_page\":null}}}}}}", PUBKEY);
        let (base, calls) = start_mock_routes(vec![("GET /ssh_keys?page=1&per_page=50".into(), 200, listed)]);
        let config = json!({"base_url": base, "token": "hetzner-token"});
        let (report, _) = hetzner_sync(&config, &[("DEPLOY".to_string(), format!("  {}\n", PUBKEY))], &[]).await.expect("hetzner sync");
        assert!(report.contains("unchanged=1"), "{}", report);
        assert!(calls.lock().unwrap().iter().all(|(m, _, _, _)| m == "GET"));
    }

    struct LocalSsh { port: u16, key: String, pub host_key: String, dir: std::path::PathBuf, child: std::process::Child }
    impl Drop for LocalSsh { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); } }
    fn start_local_ssh() -> LocalSsh {
        let dir = std::env::temp_dir().join(format!("openwarp-ssh-test-{}-{}", std::process::id(), openwarp_crypto::b64(&openwarp_crypto::random_key()).chars().take(8).collect::<String>()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = |name: &str| format!("{}\n", std::process::Command::new("ssh-keygen").args(["-t","ed25519","-f",&format!("{}/{}", dir.display(), name),"-N",""]).output().unwrap().status);
        let _ = bin("host"); let _ = bin("user");
        let host_pub = std::fs::read_to_string(dir.join("host.pub")).unwrap();
        let host_key = host_pub.split_whitespace().nth(1).unwrap_or("").to_string();
        let host_type = host_pub.split_whitespace().next().unwrap_or("").to_string();
        let user_pub = std::fs::read_to_string(dir.join("user.pub")).unwrap();
        let auth = dir.join("authorized"); std::fs::write(&auth, &user_pub).unwrap();
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)); }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sshd = std::process::Command::new("which").arg("sshd").output().ok().and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default();
        let sshd = sshd.trim();
        let sshd = if sshd.is_empty() { "/usr/sbin/sshd" } else { sshd };
        let mut cmd = std::process::Command::new(sshd);
        cmd.args(["-f","/dev/null","-D","-e","-h"]).arg(dir.join("host")).args(["-o", &format!("Port={}", port), "-o", "ListenAddress=127.0.0.1", "-o", &format!("AuthorizedKeysFile={}", auth.display()), "-o", "PasswordAuthentication=no", "-o", "PubkeyAuthentication=yes", "-o", "StrictModes=no", "-o", &format!("PidFile={}", dir.join("sshd.pid").display()), "-o", "UsePAM=no"]);
        drop(listener);
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("sshd must be installed to run the ssh file sync test");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{}", port).parse().unwrap(), std::time::Duration::from_millis(100)).is_err() {
            if std::time::Instant::now() > deadline {
                let mut err = String::new();
                if let Some(mut stderr) = child.stderr.take() { use std::io::Read; let _ = stderr.read_to_string(&mut err); }
                panic!("sshd did not accept connections on port {}: {}", port, err);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        LocalSsh { port, key: std::fs::read_to_string(dir.join("user")).unwrap(), host_key: format!("127.0.0.1 {} {}", host_type, host_key), dir, child }
    }

    #[tokio::test]
    async fn ssh_file_sync_splits_folders_and_prunes_only_its_own_names() {
        let server = start_local_ssh();
        let env_file = server.dir.join("env"); let db_file = server.dir.join("db");
        let (key, host_key) = (server.key.clone(), server.host_key.clone());
        let config = json!({"host":"127.0.0.1","port":server.port,"user":std::env::var("USER").unwrap(),"private_key":key,"known_hosts":host_key,"mode":"mirror","files":[{"path":env_file,"format":"dotenv","folders":["/app"],"file_mode":"600"},{"path":db_file,"format":"json","folders":["/db"]}]});
        let secrets = vec![("/app".into(),"API_KEY".into(),"v1".into(),"secret".into()),("/db".into(),"DB_URL".into(),"postgres://db".into(),"secret".into()),("/other".into(),"SKIP".into(),"nope".into(),"secret".into())];
        let (report, managed) = ssh_file_sync(&config, &secrets, &[]).await.expect("first sync");
        assert!(report.contains(&format!("{}: created=1", env_file.display())), "{}", report);
        assert!(report.contains(&format!("{}: created=1", db_file.display())), "{}", report);
        let env = std::fs::read_to_string(&env_file).unwrap();
        assert!(env.contains("API_KEY=v1"), "{}", env);
        assert!(!env.contains("SKIP") && !env.contains("DB_URL"), "a folder only feeds its own file: {}", env);
        let db: Value = serde_json::from_str(&std::fs::read_to_string(&db_file).unwrap()).unwrap();
        assert_eq!(db["DB_URL"], "postgres://db");
        assert_eq!(managed, vec![format!("{}|API_KEY", env_file.display()), format!("{}|DB_URL", db_file.display())]);
        // A name this integration does not own survives a mirror sync.
        std::fs::write(&env_file, "API_KEY=v1\nFOREIGN=keep\n").unwrap();
        let (report, _) = ssh_file_sync(&config, &[("/app".into(),"API_KEY".into(),"v2".into(),"secret".into())], &managed).await.expect("second sync");
        assert!(report.contains("updated=1"), "{}", report);
        let env = std::fs::read_to_string(&env_file).unwrap();
        assert!(env.contains("API_KEY=v2") && env.contains("FOREIGN=keep"), "{}", env);
        let (report, _) = ssh_file_sync(&config, &[], &managed).await.expect("mirror");
        assert!(report.contains("deleted=1"), "{}", report);
        let env = std::fs::read_to_string(&env_file).unwrap();
        assert!(!env.contains("API_KEY") && env.contains("FOREIGN=keep"), "mirror removes only owned names: {}", env);
        let imported = ssh_file_pull(&config).await.expect("pull");
        assert!(imported.iter().any(|(k, v)| k == "FOREIGN" && v == "keep"), "{:?}", imported);
    }

    #[tokio::test]
    async fn ssh_file_sync_refuses_an_unknown_host_key() {
        let server = start_local_ssh();
        let target = server.dir.join("refused");
        let key = server.key.clone();
        let config = json!({"host":"127.0.0.1","port":server.port,"user":std::env::var("USER").unwrap(),"private_key":key,"known_hosts":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIThisIsNotARealKeyItIsATestFixtureOnlyAAAA","path":target});
        let err = ssh_file_sync(&config, &[("/".into(),"API_KEY".into(),"v".into(),"secret".into())], &[]).await.unwrap_err();
        assert!(err.to_lowercase().contains("host key") || err.contains("verification"), "{}", err);
        assert!(!target.exists(), "a refused host must not be written");
    }

    #[tokio::test]
    async fn ssh_file_sync_renders_each_format_and_a_dry_run_writes_nothing() {
        let server = start_local_ssh();
        let yaml = server.dir.join("app.yaml"); let exported = server.dir.join("app.exports");
        let (key, host_key) = (server.key.clone(), server.host_key.clone());
        let base = json!({"host":"127.0.0.1","port":server.port,"user":std::env::var("USER").unwrap(),"private_key":key,"known_hosts":host_key});
        let mut dry = base.clone(); dry["dry_run"] = json!(true); dry["path"] = json!(yaml);
        let (report, managed) = ssh_file_sync(&dry, &[("/".into(),"API_KEY".into(),"v".into(),"secret".into())], &[]).await.expect("dry run");
        assert!(report.contains("dry-run") && report.contains("created=1"), "{}", report);
        assert!(managed.is_empty(), "a dry run must not record ownership");
        assert!(!yaml.exists(), "a dry run must not create the file");
        let mut live = base.clone();
        let csv = server.dir.join("app.csv");
        live["files"] = json!([{"path":yaml,"format":"yaml","folders":["/app"]},{"path":exported,"format":"export","folders":["/ops"]},{"path":csv,"format":"csv","folders":["/sheet"]}]);
        let secrets = vec![("/app".into(),"API_KEY".into(),"a b".into(),"secret".into()),("/ops".into(),"TOKEN".into(),"x".into(),"secret".into()),("/sheet".into(),"ROW".into(),"1".into(),"secret".into())];
        ssh_file_sync(&live, &secrets, &[]).await.expect("sync");
        let yaml_text = std::fs::read_to_string(&yaml).unwrap();
        assert!(yaml_text.starts_with("# Synced by OpenWarp at "), "yaml records when it was written: {}", yaml_text);
        assert!(yaml_text.contains("API_KEY: 'a b'"), "yaml quotes a value with spaces: {}", yaml_text);
        assert!(!yaml_text.contains("TOKEN"), "yaml only carries its folder: {}", yaml_text);
        let export_text = std::fs::read_to_string(&exported).unwrap();
        assert!(export_text.contains("export TOKEN=x\n"), "{}", export_text);
        let csv_text = std::fs::read_to_string(&csv).unwrap();
        assert_eq!(csv_text, "key,value\nROW,1\n", "csv has no comment syntax: {}", csv_text);
        let quoted = ssh_render("csv", &std::iter::once(("NOTE".into(), "a, \"b\"".into())).collect(), "");
        let parsed = ssh_parse("csv", &quoted).unwrap();
        assert_eq!(parsed.get("NOTE").map(String::as_str), Some("a, \"b\""), "csv quoting round-trips: {}", quoted);
        let mut quiet = base.clone(); quiet["comment"] = json!(false); quiet["path"] = json!(server.dir.join("quiet.env")); quiet["format"] = json!(".env");
        ssh_file_sync(&quiet, &[("/".into(),"API_KEY".into(),"v".into(),"secret".into())], &[]).await.expect("quiet");
        let quiet_text = std::fs::read_to_string(server.dir.join("quiet.env")).unwrap();
        assert_eq!(quiet_text, "API_KEY=v\n", ".env is dotenv, and comment:false omits the stamp: {}", quiet_text);
        let mut overlap = base.clone();
        overlap["files"] = json!([{"path":"/tmp/a","folders":["/"]},{"path":"/tmp/b","folders":["/"]}]);
        let err = ssh_file_sync(&overlap, &secrets, &[]).await.unwrap_err();
        assert!(err.contains("claimed by both"), "{}", err);
    }

    #[tokio::test]
    async fn resend_rotation_creates_then_revokes_the_previous_key() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("POST /api-keys", 201, r#"{"id":"new-key","token":"re_new"}"#),
            ("DELETE /api-keys/old-key", 200, r#"{"deleted":true}"#),
        ]));
        let config = json!({"kind":"resend","api_key":"re_admin","key_id":"old-key","base_url":base});
        let rotated = rotate_value(&config, "MAIL_KEY", "/").await.expect("rotate").expect("adapter");
        assert_eq!(rotated.value, "re_new");
        assert_eq!(rotated.config["key_id"], "new-key");
        let cleanup = rotated.cleanup.expect("cleanup");
        assert_eq!(cleanup["id"], "old-key");
        assert_eq!(rotated.rollback.expect("rollback")["id"], "new-key");
        finalize_rotation(&cleanup).await.expect("cleanup");
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/api-keys").expect("create");
        assert!(create.2.contains("Bearer re_admin"));
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/api-keys/old-key"));
    }

    #[tokio::test]
    async fn openrouter_and_openai_rotation_replace_the_previous_credential() {
        let (base, calls) = start_mock_routes(mock_routes(&[
            ("POST /keys", 201, r#"{"key":"sk-or-new","data":{"hash":"newhash"}}"#),
            ("DELETE /keys/oldhash", 200, r#"{"deleted":true}"#),
            ("POST /organization/projects/proj_1/service_accounts/svc_1/api_keys", 200, r#"{"id":"newid","value":"sk-new"}"#),
            ("DELETE /organization/projects/proj_1/api_keys/oldid", 200, r#"{"deleted":true}"#),
        ]));
        let openrouter = json!({"kind":"openrouter","management_key":"sk-or-admin","hash":"oldhash","base_url":base});
        let rotated = rotate_value(&openrouter, "MODEL_KEY", "/").await.expect("rotated").expect("adapter");
        assert_eq!(rotated.value, "sk-or-new");
        assert_eq!(rotated.config["hash"], "newhash");
        finalize_rotation(&rotated.cleanup.expect("cleanup")).await.expect("revoke");
        let openai = json!({"kind":"openai","admin_key":"sk-admin","project_id":"proj_1","service_account_id":"svc_1","id":"oldid","base_url":base});
        let rotated = rotate_value(&openai, "OPENAI_KEY", "/").await.expect("rotated").expect("adapter");
        assert_eq!(rotated.value, "sk-new");
        assert_eq!(rotated.config["id"], "newid");
        finalize_rotation(&rotated.cleanup.expect("cleanup")).await.expect("revoke");
        let calls = calls.lock().unwrap();
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/keys/oldhash"));
        assert!(calls.iter().any(|(m, p, _, _)| m == "DELETE" && p == "/organization/projects/proj_1/api_keys/oldid"));
    }

    #[tokio::test]
    async fn rotation_adapter_rejects_unknown_kinds_and_missing_values() {
        let config = json!({"kind":"not-a-provider"});
        assert!(rotate_value(&config, "KEY", "/").await.is_err());
        let (base, _) = start_mock_routes(mock_routes(&[("POST /rotate", 200, r#"{"ok":true}"#)]));
        let relay = json!({"rotation_url": format!("{}/rotate", base)});
        assert!(rotate_value(&relay, "KEY", "/").await.is_err());
    }

    #[test]
    fn rotation_config_validation_rejects_incomplete_adapters() {
        assert!(validate_rotation_config(&json!({})).is_ok());
        assert!(validate_rotation_config(&json!({"kind":"resend","api_key":"re_parent"})).is_ok());
        assert!(validate_rotation_config(&json!({"kind":"resend"})).is_err());
        assert!(validate_rotation_config(&json!({"kind":"openrouter","management_key":"sk-or"})).is_ok());
        assert!(validate_rotation_config(&json!({"kind":"openrouter"})).is_err());
        assert!(validate_rotation_config(&json!({"kind":"openai","admin_key":"sk","project_id":"p","service_account_id":"s"})).is_ok());
        assert!(validate_rotation_config(&json!({"kind":"openai","admin_key":"sk"})).is_err());
        assert!(validate_rotation_config(&json!({"kind":"nope"})).is_err());
        assert!(validate_rotation_config(&json!({"rotation_url":"https://rotate.example.com/hook"})).is_ok());
    }

    #[tokio::test]
    async fn generic_rotation_relay_uses_the_returned_value() {
        let (base, calls) = start_mock_routes(mock_routes(&[("POST /rotate", 200, r#"{"value":"rotated-value"}"#)]));
        let config = json!({"rotation_url": format!("{}/rotate", base), "provider": "custom", "rotation_token": "tok"});
        let rotated = rotate_value(&config, "CUSTOM_KEY", "/team").await.expect("rotate").expect("adapter");
        assert_eq!(rotated.value, "rotated-value");
        assert!(rotated.cleanup.is_none());
        let calls = calls.lock().unwrap();
        let request = calls.iter().find(|(m, p, _, _)| m == "POST" && p == "/rotate").expect("relay");
        assert!(request.2.contains("Bearer tok"));
        let body: Value = serde_json::from_str(&request.3).expect("json");
        assert_eq!(body["key"], "CUSTOM_KEY");
        assert_eq!(body["path"], "/team");
        assert_eq!(body["provider"], "custom");
    }

}
#[cfg(target_arch = "wasm32")]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn oci_vault_sync(_config: &Value, _secrets: &[(String, String)], _previous: &[String]) -> Result<(String, Vec<String>), String> { Err("OCI Vault sync needs RSA request signing, which requires the native server".into()) }
#[cfg(target_arch = "wasm32")]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn oci_vault_test(_config: &Value) -> Result<String, String> { Err("OCI Vault needs RSA request signing, which requires the native server".into()) }
#[cfg(target_arch = "wasm32")]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn ssh_file_sync(_config: &Value, _secrets: &[(String, String, String, String)], _previous: &[String]) -> Result<(String, Vec<String>), String> { Err("SSH file sync needs the native server: a Worker cannot run ssh".into()) }
#[cfg(target_arch = "wasm32")]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn ssh_file_test(_config: &Value) -> Result<String, String> { Err("SSH file sync needs the native server: a Worker cannot run ssh".into()) }
#[cfg(target_arch = "wasm32")]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_arch = "wasm32"))]
pub async fn ssh_file_pull(_config: &Value) -> Result<Vec<(String, String)>, String> { Err("SSH file sync needs the native server: a Worker cannot run ssh".into()) }
#[cfg(target_arch = "wasm32")]
pub fn ssh_owned_names(_config: &Value, _secrets: &[(String, String, String, String)]) -> Result<Vec<String>, String> { Err("SSH file sync needs the native server: a Worker cannot run ssh".into()) }
