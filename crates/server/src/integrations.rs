use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use std::collections::{BTreeMap, HashMap};
type HmacSha256 = Hmac<Sha256>;

pub const KINDS: &[&str] = &["github","gitlab","vercel","netlify","cloudflare","cloudflare_pages","trigger","supabase","nomad","coolify","aws_secrets_manager","aws_parameter_store","gcp_secret_manager","azure_key_vault","digitalocean","railway","render","flyio","heroku","kubernetes","hashicorp_vault","webhook","instabox","boat","daytona","onepassword","dokploy","caprover","portainer","docker_swarm"];

fn http_client() -> reqwest::Client { reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| reqwest::Client::builder().build().expect("http client")) }
fn cfg<'a>(c: &'a Value, k: &str) -> &'a str { c.get(k).and_then(|v| v.as_str()).unwrap_or("") }
fn base(c: &Value, default: &str) -> String { let b = cfg(c, "base_url"); if b.is_empty() { default.to_string() } else { b.trim_end_matches('/').to_string() } }
async fn req(r: reqwest::RequestBuilder) -> Result<String, String> {
    let resp = r.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if status.is_success() { Ok(text) } else { Err(format!("HTTP {}: {}", status, text.chars().take(400).collect::<String>())) }
}
fn map_json(secrets: &[(String, String)]) -> Value { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); } Value::Object(m) }

pub async fn sync(kind: &str, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    let client = http_client();
    match kind {
        "supabase" => { let items: Vec<Value> = secrets.iter().map(|(k,v)| json!({"name":k,"value":v})).collect();
            req(client.post(format!("{}/v1/projects/{}/secrets", base(config,"https://api.supabase.com"), cfg(config,"project_ref"))).bearer_auth(cfg(config,"token")).json(&items)).await?; Ok(format!("pushed {} secrets to Supabase", secrets.len())) }
        "nomad" => { req(client.put(format!("{}/v1/var/openwarp/default", base(config,"http://127.0.0.1:4646"))).header("X-Nomad-Token", cfg(config,"token")).json(&json!({"Items": map_json(secrets)}))).await?; Ok("pushed to Nomad variables".into()) }
        "coolify" => { for (k, v) in secrets { req(client.post(format!("{}/api/v1/applications/{}/envs", base(config,"https://app.coolify.io"), cfg(config,"app_uuid"))).bearer_auth(cfg(config,"token")).json(&json!({"key":k,"value":v,"is_preview":false}))).await?; } Ok(format!("pushed {} secrets to Coolify", secrets.len())) }
        "cloudflare_pages" => { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!({"value":v,"type":"secret_text"})); }
            req(client.put(format!("{}/client/v4/accounts/{}/pages/projects/{}/deployment_configs/production", base(config,"https://api.cloudflare.com"), cfg(config,"account_id"), cfg(config,"project"))).bearer_auth(cfg(config,"token")).json(&json!({"env_vars": Value::Object(m)}))).await?; Ok("pushed to Cloudflare Pages".into()) }
        "webhook" => { req(client.post(cfg(config,"url")).json(&json!({"secrets": map_json(secrets)})).header("Authorization", format!("Bearer {}", cfg(config,"token")))).await?; Ok(format!("pushed {} secrets to webhook", secrets.len())) }
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
        "gcp_secret_manager" => { let project = cfg(config,"project"); for (k, v) in secrets { let name = k.to_lowercase().replace('_',"-");
                let _ = client.post(format!("{}/v1/projects/{}/secrets?secretId={}", base(config,"https://secretmanager.googleapis.com"), project, name)).bearer_auth(cfg(config,"token")).json(&json!({"replication":{"automatic":{}}})).send().await;
                req(client.post(format!("{}/v1/projects/{}/secrets/{}:addVersion", base(config,"https://secretmanager.googleapis.com"), project, name)).bearer_auth(cfg(config,"token")).json(&json!({"payload":{"data": openwarp_crypto::b64(v.as_bytes())}}))).await?; }
            Ok(format!("pushed {} secrets to GCP Secret Manager", secrets.len())) }
        "azure_key_vault" => { for (k, v) in secrets { let name = k.to_lowercase().replace('_',"-");
                req(client.put(format!("{}/secrets/{}?api-version=7.4", if cfg(config,"base_url").is_empty() { format!("https://{}.vault.azure.net", cfg(config,"vault")) } else { base(config,"") }, name)).bearer_auth(cfg(config,"token")).json(&json!({"value":v}))).await?; }
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
fn trigger_desired(config: &Value, secrets: &[(String, String)]) -> Vec<(String, String)> {
    let prefix = cfg(config, "prefix"); let include: Vec<String> = config.get("include_keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let exclude: Vec<String> = config.get("exclude_keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    secrets.iter().filter(|(k, _)| (include.is_empty() || include.contains(k)) && !exclude.contains(k)).map(|(k, v)| (format!("{}{}", prefix, k), v.clone())).filter(|(n, _)| seen.insert(n.clone())).collect()
}
pub fn desired_names(config: &Value, secrets: &[(String, String)]) -> Vec<String> { trigger_desired(config, secrets).into_iter().map(|(n, _)| n).collect() }
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

async fn instabox_list(client: &reqwest::Client, root: &reqwest::Url, key: &str) -> Result<Vec<String>, String> {
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
async fn boat_find_env(client: &reqwest::Client, api: &str, key: &str, want: &str, org: &str) -> Result<(String, String, Value), String> {
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
async fn daytona_send(key: &str, org: &str, r: reqwest::RequestBuilder) -> Result<String, String> {
    let r = if org.is_empty() { r.bearer_auth(key) } else { r.bearer_auth(key).header("X-Daytona-Organization-ID", org) };
    req(r).await }
async fn daytona_secret_list(client: &reqwest::Client, key: &str, org: &str, api: &str) -> Result<Vec<Value>, String> {
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

async fn github_sync(client: &reqwest::Client, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
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
async fn aws_signed(client: &reqwest::Client, r: AwsReq<'_>) -> Result<String, String> {
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
async fn aws_call(client: &reqwest::Client, config: &Value, service: &str, region: &str, ak: &str, sk: &str, target: &str, payload: &Value) -> Result<Value, String> {
    let body = payload.to_string();
    let text = aws_signed(client, AwsReq { service, region, ak, sk, session_token: cfg(config, "session_token"), target, payload: &body, endpoint: cfg(config, "endpoint") }).await?;
    if text.trim().is_empty() { Ok(json!({})) } else { serde_json::from_str(&text).map_err(|e| format!("AWS {} returned invalid JSON: {}", target, e)) }
}
fn aws_creds(config: &Value) -> Result<(&str, &str, &str), String> {
    let (region, ak, sk) = (cfg(config, "region"), cfg(config, "access_key_id"), cfg(config, "secret_access_key"));
    if region.is_empty() || ak.is_empty() || sk.is_empty() { return Err("AWS integration requires region, access_key_id, secret_access_key".into()); }
    Ok((region, ak, sk))
}
fn aws_secret_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 512 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+=.@-".contains(&b))
}
fn ssm_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 1011 && !name.contains(' ') && !name.contains("//") && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
}

async fn aws_sm_list(client: &reqwest::Client, config: &Value, region: &str, ak: &str, sk: &str) -> Result<Vec<String>, String> {
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
    let (region, ak, sk) = aws_creds(config)?;
    let mode = sync_mode(config, "aws_secrets_manager")?;
    let dry = is_dry(config);
    let mapping = { let m = cfg(config, "mapping"); if !m.is_empty() { m } else if !cfg(config, "secret_id").is_empty() { "many_to_one" } else { "one_to_one" } };
    let client = http_client();
    if mapping == "many_to_one" {
        let secret_id = cfg(config, "secret_id");
        if secret_id.is_empty() { return Err("aws_secrets_manager many_to_one requires secret_id".into()); }
        if mode == "mirror" { return Err("aws_secrets_manager many_to_one cannot mirror keys; use mapping one_to_one".into()); }
        let json_body = map_json(secrets).to_string();
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
        return Ok((format!("AWS Secrets Manager sync{}: wrote {} keys into {}", if dry { " (dry-run)" } else { "" }, secrets.len(), secret_id), Vec::new()));
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
    let (region, ak, sk) = aws_creds(config)?;
    let value = aws_call(&http_client(), config, "secretsmanager", region, ak, sk, "secretsmanager.ListSecrets", &json!({"MaxResults": 1})).await?;
    let count = value.get("SecretList").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    Ok(format!("AWS Secrets Manager connection OK: region {} returned a secret list ({} item(s))", region, count))
}

fn ssm_path(config: &Value) -> String {
    let path = cfg(config, "path_prefix").trim_end_matches('/');
    if path.is_empty() { String::new() } else if path.starts_with('/') { path.to_string() } else { format!("/{}", path) }
}
async fn ssm_list(client: &reqwest::Client, config: &Value, region: &str, ak: &str, sk: &str) -> Result<Vec<String>, String> {
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
async fn onepassword_items(client: &reqwest::Client, base: &str, token: &str, vault: &str) -> Result<Vec<Value>, String> {
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
    let mode = sync_mode(config, "onepassword")?;
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
    let text = req(client.get(read_url).header("x-api-key", &key)).await.map_err(|e| format!("Dokploy read failed: {}", e))?;
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
async fn caprover_auth(client: &reqwest::Client, config: &Value) -> Result<(String, String), String> {
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
async fn caprover_apps(client: &reqwest::Client, api: &str, token: &str) -> Result<Vec<Value>, String> {
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
async fn portainer_stacks(client: &reqwest::Client, base: &str, key: &str) -> Result<Vec<Value>, String> {
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
fn docker_client(config: &Value) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none());
    let cert = cfg(config, "client_cert"); let key = cfg(config, "client_key"); let ca = cfg(config, "ca_cert");
    if !cert.is_empty() || !key.is_empty() {
        if cert.is_empty() || key.is_empty() { return Err("Docker requires both client_cert and client_key".into()); }
        let identity = reqwest::Identity::from_pem(format!("{}\n{}", cert, key).as_bytes()).map_err(|e| format!("Docker client certificate is invalid: {}", e))?;
        builder = builder.identity(identity);
    }
    if !ca.is_empty() { builder = builder.add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).map_err(|e| format!("Docker CA certificate is invalid: {}", e))?); }
    if config.get("insecure").and_then(Value::as_bool).unwrap_or(false) { builder = builder.danger_accept_invalid_certs(true); }
    builder.build().map_err(|e| e.to_string())
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

pub fn has_test(kind: &str) -> bool {
    matches!(kind, "trigger" | "instabox" | "boat" | "daytona" | "aws_secrets_manager" | "aws_parameter_store" | "onepassword" | "dokploy" | "caprover" | "portainer" | "docker_swarm")
}
pub async fn test(kind: &str, config: &Value) -> Result<String, String> {
    match kind {
        "trigger" => trigger_test(config).await,
        "instabox" => instabox_test(config).await,
        "boat" => boat_test(config).await,
        "daytona" => daytona_test(config).await,
        "aws_secrets_manager" => aws_secrets_manager_test(config).await,
        "aws_parameter_store" => aws_parameter_store_test(config).await,
        "onepassword" => onepassword_test(config).await,
        "dokploy" => dokploy_test(config).await,
        "caprover" => caprover_test(config).await,
        "portainer" => portainer_test(config).await,
        "docker_swarm" => docker_swarm_test(config).await,
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
    let endpoint = cfg(config, "endpoint");
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
fn chrono_now() -> String {
    // YYYYMMDDTHHMMSSZ from unix time without chrono dep
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
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
                sink.lock().unwrap().push((method.clone(), path.clone(), head.clone(), body));
                let key = format!("{} {} {}", method, path, head);
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
        let config = json!({"region":"us-east-1","access_key_id":"AKIA","secret_access_key":"secret","endpoint":base,"secret_id":"app/prod"});
        let secrets = vec![("API_KEY".to_string(), "v1".to_string())];
        let (_report, managed) = aws_secrets_manager_sync(&config, &secrets, &[]).await.expect("aws sm sync");
        assert!(managed.is_empty());
        let calls = calls.lock().unwrap();
        let create = calls.iter().find(|(_, _, head, _)| head.contains("secretsmanager.CreateSecret")).expect("create call");
        assert!(create.3.contains("\"Name\":\"app/prod\""), "{}", create.3);
        let body: Value = serde_json::from_str(&create.3).expect("json body");
        let nested: Value = serde_json::from_str(body["SecretString"].as_str().expect("secret string")).expect("nested json");
        assert_eq!(nested["API_KEY"], "v1");
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
}
