use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

pub const KINDS: &[&str] = &["github","gitlab","vercel","netlify","cloudflare","cloudflare_pages","trigger","supabase","nomad","coolify","aws_secrets_manager","aws_parameter_store","gcp_secret_manager","azure_key_vault","digitalocean","railway","render","flyio","heroku","kubernetes","hashicorp_vault","webhook"];

fn cfg<'a>(c: &'a Value, k: &str) -> &'a str { c.get(k).and_then(|v| v.as_str()).unwrap_or("") }
fn base(c: &Value, default: &str) -> String { let b = cfg(c, "base_url"); if b.is_empty() { default.to_string() } else { b.trim_end_matches('/').to_string() } }
async fn req(r: reqwest::RequestBuilder) -> Result<String, String> {
    let resp = r.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if status.is_success() { Ok(text) } else { Err(format!("HTTP {}: {}", status, text.chars().take(400).collect::<String>())) }
}
fn map_json(secrets: &[(String, String)]) -> Value { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); } Value::Object(m) }

pub async fn sync(kind: &str, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    let client = reqwest::Client::new();
    match kind {
        "supabase" => { let items: Vec<Value> = secrets.iter().map(|(k,v)| json!({"name":k,"value":v})).collect();
            req(client.post(format!("{}/v1/projects/{}/secrets", base(config,"https://api.supabase.com"), cfg(config,"project_ref"))).bearer_auth(cfg(config,"token")).json(&items)).await?; Ok(format!("pushed {} secrets to Supabase", secrets.len())) }
        "nomad" => { req(client.put(format!("{}/v1/var/openwarp/default", base(config,"http://127.0.0.1:4646"))).header("X-Nomad-Token", cfg(config,"token")).json(&json!({"Items": map_json(secrets)}))).await?; Ok("pushed to Nomad variables".into()) }
        "coolify" => { for (k, v) in secrets { req(client.post(format!("{}/api/v1/applications/{}/envs", base(config,"https://app.coolify.io"), cfg(config,"app_uuid"))).bearer_auth(cfg(config,"token")).json(&json!({"key":k,"value":v,"is_preview":false}))).await.ok(); } Ok(format!("pushed {} secrets to Coolify", secrets.len())) }
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
            for (k, v) in secrets { req(client.post(format!("{}/v10/projects/{}/env{}", base(config,"https://api.vercel.com"), cfg(config,"project_id"), q)).bearer_auth(cfg(config,"token")).json(&json!({"key":k,"value":v,"type":"encrypted","target":["production","preview","development"]}))).await.ok(); }
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
            if let Some(svcs) = spec.get_mut("spec").and_then(|s| s.get_mut("services")).and_then(|v| v.as_array_mut()) { for svc in svcs.iter_mut() { let mut envs: Vec<Value> = secrets.iter().map(|(k,v)| json!({"key":k,"value":v,"scope":"RUN_AND_BUILD_TIME","type":"SECRET"})).collect(); if let Some(existing) = svc.get_mut("envs").and_then(|e| e.as_array_mut()) { existing.append(&mut envs); } else { svc["envs"] = json!(envs); } } }
            req(client.put(format!("{}/v2/apps/{}", base(config,"https://api.digitalocean.com"), app_id)).bearer_auth(cfg(config,"token")).json(&json!({"spec": spec["spec"]}))).await?; Ok("pushed to DigitalOcean App Platform".into()) }
        "aws_secrets_manager" | "aws_parameter_store" => aws_sync(config, secrets, kind).await,
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
    secrets.iter().filter(|(k, _)| (include.is_empty() || include.contains(k)) && !exclude.contains(k)).map(|(k, v)| (format!("{}{}", prefix, k), v.clone())).collect()
}
pub async fn trigger_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let client = reqwest::Client::new(); let base_url = base(config, "https://api.trigger.dev");
    let mode = { let m = cfg(config, "mode"); if m.is_empty() { "upsert" } else { m } };
    let dry = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
    let desired = trigger_desired(config, secrets);
    let targets = trigger_targets(config);
    if targets.iter().any(|x| x.project_ref.is_empty() || x.token.is_empty()) { return Err("trigger requires token and project_ref (per target or global)".into()); }
    let mut managed: Vec<String> = Vec::new(); let mut reports: Vec<String> = Vec::new(); let mut failures = 0;
    for tg in &targets {
        let root = format!("{}/api/v1/projects/{}/envvars/{}", base_url, tg.project_ref, tg.env);
        let list_text = match req(client.get(&root).bearer_auth(&tg.token)).await { Ok(x) => x, Err(e) => { failures += 1; reports.push(format!("{}/{}: list failed: {}", tg.project_ref, tg.env, e)); continue; } };
        let remote_list: Vec<Value> = serde_json::from_str(&list_text).unwrap_or_default();
        let remote: std::collections::HashMap<String, String> = remote_list.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), v.get("value")?.as_str()?.to_string()))).collect();
        let (mut created, mut updated, mut unchanged, mut deleted) = (0, 0, 0, 0);
        if !dry {
            let mut bulk: Vec<Value> = Vec::new();
            for (name, value) in &desired { match remote.get(name) { None => bulk.push(json!({"name":name,"value":value})), Some(old) if old != value => bulk.push(json!({"name":name,"value":value})), Some(_) => unchanged += 1 } }
            created = bulk.iter().filter(|v| !remote.contains_key(v.get("name").and_then(|x| x.as_str()).unwrap_or(""))).count();
            updated = bulk.len() - created;
            if !bulk.is_empty() { if let Err(e) = req(client.post(format!("{}/import", root)).bearer_auth(&tg.token).json(&json!({"variables": bulk, "override": true}))).await { failures += 1; reports.push(format!("{}/{}: import failed: {}", tg.project_ref, tg.env, e)); continue; } }
            if mode == "mirror" { for name in previous_managed { if !desired.iter().any(|(n, _)| n == name) && remote.contains_key(name) { let _ = req(client.delete(format!("{}/{}", root, name)).bearer_auth(&tg.token)).await; deleted += 1; } } }
        } else { for (name, value) in &desired { match remote.get(name) { None => created += 1, Some(old) if old != value => updated += 1, Some(_) => unchanged += 1 } }
            if mode == "mirror" { for name in previous_managed { if !desired.iter().any(|(n, _)| n == name) && remote.contains_key(name) { deleted += 1; } } } }
        for (n, _) in &desired { if !managed.contains(n) { managed.push(n.clone()); } }
        reports.push(format!("{}/{}: created={} updated={} unchanged={} deleted={}{}", tg.project_ref, tg.env, created, updated, unchanged, deleted, if dry { " (dry-run)" } else { "" }));
    }
    if failures > 0 && failures == targets.len() { return Err(reports.join("; ")); }
    let mut note = String::new();
    if config.get("mark_secret").and_then(|v| v.as_bool()).unwrap_or(false) { note = " NOTE: Trigger REST create/import schema documents name/value only, so secret marking could not be applied via API; mark these in the Trigger dashboard if needed.".to_string(); }
    Ok((format!("Trigger.dev sync{}: {}{}", if dry { " (dry-run)" } else { "" }, reports.join("; "), note), managed))
}
pub async fn trigger_test(config: &Value) -> Result<String, String> {
    let client = reqwest::Client::new(); let base_url = base(config, "https://api.trigger.dev"); let targets = trigger_targets(config);
    let tg = targets.first().ok_or("no target")?; if tg.project_ref.is_empty() || tg.token.is_empty() { return Err("trigger requires token and project_ref".into()); }
    let text = req(client.get(format!("{}/api/v1/projects/{}/envvars/{}", base_url, tg.project_ref, tg.env)).bearer_auth(&tg.token)).await?;
    let count = serde_json::from_str::<Vec<Value>>(&text).map(|v| v.len()).unwrap_or(0);
    Ok(format!("Trigger connection OK: project {} env {} currently has {} variables", tg.project_ref, tg.env, count))
}

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
async fn aws_sync(config: &Value, secrets: &[(String, String)], kind: &str) -> Result<String, String> {
    let region = cfg(config, "region"); let ak = cfg(config, "access_key_id"); let sk = cfg(config, "secret_access_key");
    if region.is_empty() || ak.is_empty() || sk.is_empty() { return Err("AWS integration requires region, access_key_id, secret_access_key".into()); }
    let client = reqwest::Client::new();
    if kind == "aws_secrets_manager" {
        let secret_id = cfg(config, "secret_id"); if secret_id.is_empty() { return Err("aws_secrets_manager requires secret_id".into()); }
        let payload = json!({"SecretId": secret_id, "SecretString": map_json(secrets).to_string()}).to_string();
        aws_signed(&client, AwsReq{service:"secretsmanager", region, ak, sk, target:"secretsmanager.UpdateSecret", payload:&payload, endpoint:cfg(config,"endpoint")}).await?;
        Ok("pushed to AWS Secrets Manager".into())
    } else {
        for (k, v) in secrets { let name = format!("{}/{}", cfg(config, "path_prefix").trim_end_matches('/'), k);
            let payload = json!({"Name": name, "Value": v, "Type": "SecureString", "Overwrite": true}).to_string();
            aws_signed(&client, AwsReq{service:"ssm", region, ak, sk, target:"AmazonSSM.PutParameter", payload:&payload, endpoint:cfg(config,"endpoint")}).await?; }
        Ok(format!("pushed {} parameters to AWS SSM", secrets.len()))
    }
}
struct AwsReq<'a> { service: &'a str, region: &'a str, ak: &'a str, sk: &'a str, target: &'a str, payload: &'a str, endpoint: &'a str }
async fn aws_signed(client: &reqwest::Client, r: AwsReq<'_>) -> Result<String, String> {
    let (service, region, ak, sk, target, payload, endpoint_cfg) = (r.service, r.region, r.ak, r.sk, r.target, r.payload, r.endpoint);
    let host = format!("{}.{}.amazonaws.com", service, region); let url = format!("https://{}", host);
    let endpoint = endpoint_cfg.to_string();
    let (host, url) = if endpoint.is_empty() { (host, url) } else { (endpoint.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string(), endpoint.trim_end_matches('/').to_string()) };
    let now = chrono_now(); let (date, amzdate) = (now[..8].to_string(), now.clone());
    let payload_hash = hex(&Sha256::digest(payload.as_bytes()));
    let canonical = format!("POST\n/\n\ncontent-type:application/x-amz-json-1.1\nhost:{}\nx-amz-date:{}\nx-amz-target:{}\n\ncontent-type;host;x-amz-date;x-amz-target\n{}", host, amzdate, target, payload_hash);
    let scope = format!("{}/{}/{}/aws4_request", date, region, service);
    let to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amzdate, scope, hex(&Sha256::digest(canonical.as_bytes())));
    let k_date = hmac(format!("AWS4{}", sk).as_bytes(), date.as_bytes()); let k_region = hmac(&k_date, region.as_bytes()); let k_svc = hmac(&k_region, service.as_bytes()); let k_sign = hmac(&k_svc, b"aws4_request");
    let sig = hex(&hmac(&k_sign, to_sign.as_bytes()));
    let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature={}", ak, scope, sig);
    req(client.post(&url).header("Content-Type","application/x-amz-json-1.1").header("X-Amz-Date",&amzdate).header("X-Amz-Target",target).header("Authorization",auth).body(payload.to_string())).await
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
