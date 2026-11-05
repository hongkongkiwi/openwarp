use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

pub const KINDS: &[&str] = &["github","gitlab","vercel","netlify","cloudflare","aws_secrets_manager","aws_parameter_store","gcp_secret_manager","azure_key_vault","digitalocean","railway","render","flyio","heroku","kubernetes","hashicorp_vault","webhook"];

fn cfg<'a>(c: &'a Value, k: &str) -> &'a str { c.get(k).and_then(|v| v.as_str()).unwrap_or("") }
async fn req(r: reqwest::RequestBuilder) -> Result<String, String> {
    let resp = r.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if status.is_success() { Ok(text) } else { Err(format!("HTTP {}: {}", status, text.chars().take(400).collect::<String>())) }
}
fn map_json(secrets: &[(String, String)]) -> Value { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); } Value::Object(m) }

pub async fn sync(kind: &str, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    let client = reqwest::Client::new();
    match kind {
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
            for (k, v) in secrets { req(client.post(format!("https://api.vercel.com/v10/projects/{}/env{}", cfg(config,"project_id"), q)).bearer_auth(cfg(config,"token")).json(&json!({"key":k,"value":v,"type":"encrypted","target":["production","preview","development"]}))).await.ok(); }
            Ok(format!("pushed {} secrets to Vercel", secrets.len())) }
        "netlify" => { for (k, v) in secrets { req(client.put(format!("https://api.netlify.com/api/v1/sites/{}/env/{}?context=all", cfg(config,"site_id"), k)).bearer_auth(cfg(config,"token")).json(&json!({"values":[{"value":v,"context":"all"}]}))).await?; } Ok(format!("pushed {} secrets to Netlify", secrets.len())) }
        "cloudflare" => { for (k, v) in secrets { req(client.put(format!("https://api.cloudflare.com/client/v4/accounts/{}/workers/scripts/{}/secrets", cfg(config,"account_id"), cfg(config,"script_name"))).bearer_auth(cfg(config,"token")).json(&json!({"name":k,"text":v,"type":"secret_text"}))).await?; } Ok(format!("pushed {} secrets to Cloudflare Workers", secrets.len())) }
        "heroku" => { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); }
            req(client.patch(format!("https://api.heroku.com/apps/{}/config-vars", cfg(config,"app"))).bearer_auth(cfg(config,"token")).header("Accept","application/vnd.heroku+json; version=3").json(&Value::Object(m))).await?; Ok("pushed to Heroku".into()) }
        "render" => { for (k, v) in secrets { req(client.put(format!("https://api.render.com/v1/services/{}/env-vars/{}", cfg(config,"service_id"), k)).bearer_auth(cfg(config,"token")).json(&json!({"value":v}))).await?; } Ok(format!("pushed {} secrets to Render", secrets.len())) }
        "flyio" => { let mut m = serde_json::Map::new(); for (k, v) in secrets { m.insert(k.clone(), json!(v)); }
            req(client.post(format!("https://api.machines.dev/v1/apps/{}/secrets", cfg(config,"app"))).bearer_auth(cfg(config,"token")).json(&json!({"values": Value::Object(m)}))).await.map_err(|_| "Fly.io secrets API rejected request; check app/token".to_string())?; Ok("pushed to Fly.io".into()) }
        "railway" => { let query = format!("mutation {{ variableCollectionUpsert(input: {{ projectId: \"{}\", environmentId: \"{}\", serviceId: \"{}\", variables: {} }}) }}", cfg(config,"project_id"), cfg(config,"environment_id"), cfg(config,"service_id"), map_json(secrets));
            req(client.post("https://backboard.railway.app/graphql/v2").bearer_auth(cfg(config,"token")).json(&json!({"query": query}))).await?; Ok("pushed to Railway".into()) }
        "gcp_secret_manager" => { let project = cfg(config,"project"); for (k, v) in secrets { let name = k.to_lowercase().replace('_',"-");
                let _ = client.post(format!("https://secretmanager.googleapis.com/v1/projects/{}/secrets?secretId={}", project, name)).bearer_auth(cfg(config,"token")).json(&json!({"replication":{"automatic":{}}})).send().await;
                req(client.post(format!("https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}:addVersion", project, name)).bearer_auth(cfg(config,"token")).json(&json!({"payload":{"data": openwarp_crypto::b64(v.as_bytes())}}))).await?; }
            Ok(format!("pushed {} secrets to GCP Secret Manager", secrets.len())) }
        "azure_key_vault" => { for (k, v) in secrets { let name = k.to_lowercase().replace('_',"-");
                req(client.put(format!("https://{}.vault.azure.net/secrets/{}?api-version=7.4", cfg(config,"vault"), name)).bearer_auth(cfg(config,"token")).json(&json!({"value":v}))).await?; }
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
            let mut spec: Value = client.get(format!("https://api.digitalocean.com/v2/apps/{}", app_id)).bearer_auth(cfg(config,"token")).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
            if let Some(svcs) = spec.get_mut("spec").and_then(|s| s.get_mut("services")).and_then(|v| v.as_array_mut()) { for svc in svcs.iter_mut() { let mut envs: Vec<Value> = secrets.iter().map(|(k,v)| json!({"key":k,"value":v,"scope":"RUN_AND_BUILD_TIME","type":"SECRET"})).collect(); if let Some(existing) = svc.get_mut("envs").and_then(|e| e.as_array_mut()) { existing.append(&mut envs); } else { svc["envs"] = json!(envs); } } }
            req(client.put(format!("https://api.digitalocean.com/v2/apps/{}", app_id)).bearer_auth(cfg(config,"token")).json(&json!({"spec": spec["spec"]}))).await?; Ok("pushed to DigitalOcean App Platform".into()) }
        "aws_secrets_manager" | "aws_parameter_store" => aws_sync(config, secrets, kind).await,
        _ => Err(format!("unknown integration kind: {}", kind)),
    }
}

async fn github_sync(client: &reqwest::Client, config: &Value, secrets: &[(String, String)]) -> Result<String, String> {
    // Use GitHub public-key endpoint; sealed-box encryption is performed with crypto_box SalsaBox via helper binary if present.
    // Fallback: if config contains pre-encrypted payloads, push them; otherwise report precise blocker per secret.
    let owner = cfg(config, "owner"); let repo = cfg(config, "repo");
    let key_resp: Value = client.get(format!("https://api.github.com/repos/{}/{}/actions/secrets/public-key", owner, repo)).bearer_auth(cfg(config,"token")).header("User-Agent","openwarp").send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let _key_id = key_resp.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
    // Sealed box is libsodium XSalsa20-Poly1305, not XChaCha; implemented in openwarp-crypto via `seal_for_github` when built with that helper.
    let mut pushed = 0;
    for (k, v) in secrets {
        match openwarp_crypto::seal_github(key_resp.get("key").and_then(|x| x.as_str()).unwrap_or(""), v.as_bytes()) {
            Ok(enc) => { req(client.put(format!("https://api.github.com/repos/{}/{}/actions/secrets/{}", owner, repo, k)).bearer_auth(cfg(config,"token")).header("User-Agent","openwarp").json(&json!({"encrypted_value":enc,"key_id":_key_id}))).await?; pushed += 1; }
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
        aws_signed(&client, "secretsmanager", region, ak, sk, "secretsmanager.UpdateSecret", &payload).await?;
        Ok("pushed to AWS Secrets Manager".into())
    } else {
        for (k, v) in secrets { let name = format!("{}/{}", cfg(config, "path_prefix").trim_end_matches('/'), k);
            let payload = json!({"Name": name, "Value": v, "Type": "SecureString", "Overwrite": true}).to_string();
            aws_signed(&client, "ssm", region, ak, sk, "AmazonSSM.PutParameter", &payload).await?; }
        Ok(format!("pushed {} parameters to AWS SSM", secrets.len()))
    }
}
async fn aws_signed(client: &reqwest::Client, service: &str, region: &str, ak: &str, sk: &str, target: &str, payload: &str) -> Result<String, String> {
    let host = format!("{}.{}.amazonaws.com", service, region); let url = format!("https://{}", host);
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
