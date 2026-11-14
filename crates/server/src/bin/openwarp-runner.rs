//! Customer-run sync runner. It polls a delegated environment's jobs, unwraps
//! the environment key with its own X25519 key, decrypts provider config and
//! secret values in this process, and pushes them to the provider. The server
//! never receives plaintext or provider credentials.
use openwarp_crypto as oc;
use openwarp_server::integrations;
use serde_json::{json, Value};
use std::{collections::HashMap, time::Duration};

fn env(name: &str) -> String { std::env::var(name).unwrap_or_default() }

async fn send(client: &reqwest::Client, base: &str, token: &str, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, String> {
    let mut req = client.request(method, format!("{}{}", base.trim_end_matches('/'), path)).bearer_auth(token);
    if let Some(b) = body { req = req.json(&b); }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if !status.is_success() { return Err(format!("HTTP {}: {}", status, text)); }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn decrypt_secret(env_key: &[u8;32], eid: &str, secret: &Value, field: &str) -> Result<String, String> {
    let enc = secret.get(format!("{}_enc", field)).and_then(Value::as_str).ok_or("secret ciphertext missing")?;
    let sid = secret.get("id").and_then(Value::as_str).unwrap_or("");
    let aad = format!("ow-secret:v2|{}|{}|{}", eid, sid, field);
    let raw = if enc.starts_with("ow2:") {
        let version = secret.get("version").and_then(Value::as_i64).unwrap_or(1);
        oc::decrypt_symmetric_aad(env_key, format!("{}|v{}", aad, version).as_bytes(), enc)
            .or_else(|_| oc::decrypt_symmetric_aad(env_key, aad.as_bytes(), enc))?
    } else { oc::decrypt_symmetric(env_key, enc)? };
    String::from_utf8(raw).map_err(|_| "secret plaintext is not UTF-8".into())
}
fn metadata(env_key: &[u8;32], eid: &str, secret: &Value, field: &str, legacy: &str) -> Result<String, String> {
    match secret.get(format!("{}_enc", field)) {
        None | Some(Value::Null) => Ok(secret.get(field).and_then(Value::as_str).unwrap_or(legacy).to_string()),
        Some(Value::String(enc)) if enc.is_empty() => Ok(secret.get(field).and_then(Value::as_str).unwrap_or(legacy).to_string()),
        Some(Value::String(_)) => decrypt_secret(env_key, eid, secret, field),
        Some(_) => Err("invalid encrypted secret metadata".into()),
    }
}
struct Prepared { config: Value, located: Vec<(String, String, String, String)>, tags_by_name: HashMap<String, String> }
fn prepare(job: &Value, kp: &oc::Keypair) -> Result<Prepared, String> {
    let wrapped = job.get("wrapped_key").and_then(|v| v.as_str()).ok_or("job has no wrapped_key")?;
    let raw = kp.decrypt(wrapped)?;
    let env_key: [u8;32] = raw.try_into().map_err(|_| "wrapped environment key is not 32 bytes")?;
    let config_enc = job.get("config_enc").and_then(|v| v.as_str()).ok_or("job has no config")?;
    let rest = config_enc.strip_prefix("owrunner:").ok_or("integration config is not runner-sealed")?;
    let (_runner, sealed) = rest.split_once(':').ok_or("malformed runner config")?;
    let envelope: Value = serde_json::from_slice(&kp.decrypt(sealed)?).map_err(|e| e.to_string())?;
    // The sealed box has no AAD; the context inside the plaintext proves this
    // config belongs to the integration named by the job. A blob without one is
    // not accepted, so a legacy or copied config cannot be redirected silently.
    let ctx = envelope.get("context").and_then(|v| v.as_str()).ok_or("sealed integration config has no context")?;
    let eid = job.get("env_id").and_then(|v| v.as_str()).unwrap_or("");
    let iid = job.get("integration_id").and_then(|v| v.as_str()).unwrap_or("");
    if ctx != format!("ow-integration|{}|{}", eid, iid) { return Err("integration config context does not match this job".into()); }
    let mut config = envelope.get("config").filter(|v| v.is_object()).cloned().ok_or("sealed integration config must be an object")?;
    config["_environment"] = json!(job.get("environment").and_then(Value::as_str).unwrap_or(""));
    if config.get("initial_sync").is_some_and(|v| v.as_str() != Some("overwrite")) { return Err("delegated sync supports initial_sync overwrite only; initial import requires client-side deployment".into()); }
    for flag in ["dry_run", "auto_sync"] { if config.get(flag).is_some_and(|v| !v.is_boolean()) { return Err(format!("{} must be a boolean", flag)); } }
    let kind = job.get("kind").and_then(Value::as_str).unwrap_or("");
    integrations::validate_sync_config(kind, &config)?;
    let secrets = job.get("secrets").and_then(Value::as_array).ok_or("job has no secrets array")?;
    let mut located = Vec::new(); let mut tags_by_name = HashMap::new();
    for s in secrets {
        let secret_type = s.get("secret_type").and_then(Value::as_str).ok_or("job has no secret type")?;
        if secret_type == "sealed" { return Err("sealed secrets must not enter runner jobs".into()); }
        if matches!(secret_type, "wallet_private_key" | "wallet_recovery_phrase") { return Err("wallet secrets must not enter runner jobs".into()); }
        let path = metadata(&env_key, eid, s, "path", "/")?;
        if !integrations::path_selected(&config, &path) { continue; }
        let key = decrypt_secret(&env_key, eid, s, "key")?;
        let value = decrypt_secret(&env_key, eid, s, "value")?;
        let tags = metadata(&env_key, eid, s, "tags", "")?;
        tags_by_name.entry(integrations::desired_name(&config, &key)).or_insert(tags);
        located.push((path, key, value, secret_type.to_string()));
    }
    Ok(Prepared { config, located, tags_by_name })
}

struct Report { ok: bool, code: &'static str, detail: &'static str, managed: Vec<(String, String)>, persist: bool, mode: &'static str }
impl Report {
    fn new(ok: bool, code: &'static str, detail: &'static str) -> Self { Self { ok, code, detail, managed: Vec::new(), persist: false, mode: "" } }
    fn invalid() -> Self { Self::new(false, "config_invalid", "Runner configuration or job preparation failed") }
    fn sync_failed() -> Self { Self::new(false, "sync_failed", "Provider sync failed") }
}

async fn run_sync(kind: &str, p: &Prepared, previous: &[String], previous_hashes: &Value) -> Report {
    let dry = p.config.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    let success = || if dry { Report::new(true, "dry_run_completed", "Sync dry-run completed") } else { Report::new(true, "sync_completed", "Provider sync completed") };
    if integrations::is_stateful(kind) {
        let hashes = match integrations::managed_value_hashes(kind, &p.config, &p.located) { Ok(h) => h, Err(_) => return Report::invalid() };
        let mut candidates = hashes.clone();
        for name in previous {
            if let Some(hash) = previous_hashes.get(name).and_then(Value::as_str).filter(|h| !h.is_empty()) { candidates.insert(name.clone(), hash.to_string()); }
        }
        // A failed dispatch can have applied any subset; retain ownership, not a claim of remote value equality.
        let failed = || {
            let mut report = Report::sync_failed();
            if !dry { report.managed = candidates.clone().into_iter().collect(); report.mode = "merge_only"; }
            report
        };
        let managed = match integrations::sync_managed_with_tags(kind, &p.config, &p.located, &p.tags_by_name, previous).await {
            Some(Ok((_, managed))) => managed,
            Some(Err(_)) => return failed(),
            None => return Report::invalid(),
        };
        let mut report = success();
        if dry { return report; }
        for name in managed {
            let hash = hashes.get(&name).cloned().or_else(|| {
                if previous.contains(&name) { previous_hashes.get(&name).and_then(Value::as_str).filter(|h| !h.is_empty()).map(str::to_string) } else { None }
            });
            match hash { Some(hash) => report.managed.push((name, hash)), None => return failed() }
        }
        report.persist = true;
        report
    } else {
        let pairs = integrations::secret_keys(&p.located);
        match integrations::sync_with_tags(kind, &p.config, &pairs, &p.tags_by_name).await { Ok(_) => success(), Err(_) => Report::sync_failed() }
    }
}

async fn run_test(kind: &str, config: &Value) -> Report {
    let result = match kind {
        "trigger" => integrations::trigger_test(config).await,
        "instabox" => integrations::instabox_test(config).await,
        "boat" => integrations::boat_test(config).await,
        "daytona" => integrations::daytona_test(config).await,
        _ => integrations::test(kind, config).await,
    };
    match result {
        Ok(_) => Report::new(true, "test_completed", "Provider connection test completed"),
        Err(_) => Report::new(false, "test_failed", "Provider connection test failed"),
    }
}

#[tokio::main]
async fn main() {
    let base = env("OPENWARP_URL");
    let token = env("OPENWARP_RUNNER_TOKEN");
    let secret = env("OPENWARP_RUNNER_KEY");
    if base.is_empty() || token.is_empty() || secret.is_empty() {
        eprintln!("OPENWARP_URL, OPENWARP_RUNNER_TOKEN and OPENWARP_RUNNER_KEY are required");
        std::process::exit(2);
    }
    let kp = match oc::Keypair::from_secret_b64(&secret) { Ok(k) => k, Err(_) => { eprintln!("invalid OPENWARP_RUNNER_KEY"); std::process::exit(2); } };
    let once = env("OPENWARP_RUNNER_ONCE") == "1";
    let interval = env("OPENWARP_RUNNER_INTERVAL").parse::<u64>().unwrap_or(10).max(1);
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build().expect("http client");
    loop {
        match send(&client, &base, &token, reqwest::Method::GET, "/api/runner/jobs", None).await {
            Ok(v) => {
                let jobs = v.get("jobs").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                for job in jobs {
                    let jid = job.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let job_kind = job.get("job_kind").and_then(|x| x.as_str()).unwrap_or("sync").to_string();
                    let kind = job.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let result = match prepare(&job, &kp) {
                        Ok(p) => {
                            if job_kind == "test" { run_test(&kind, &p.config).await }
                            else if job_kind == "sync" {
                                let previous: Vec<String> = job.get("previous").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
                                run_sync(&kind, &p, &previous, &job["previous_hashes"]).await
                            } else { Report::invalid() }
                        }
                        Err(_) => Report::invalid(),
                    };
                    let claim = job.get("claim").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let managed: Vec<Value> = result.managed.into_iter().map(|(name, value_hash)| json!({"name": name, "value_hash": value_hash})).collect();
                    let body = json!({"ok": result.ok, "code": result.code, "detail": result.detail, "managed": managed,
                        "claim": claim, "job_id": jid, "persist_managed": result.persist, "managed_mode": result.mode});
                    if send(&client, &base, &token, reqwest::Method::POST, &format!("/api/runner/jobs/{}/result", jid), Some(body)).await.is_err() {
                        eprintln!("runner result delivery failed");
                    }
                }
            }
            Err(_) => eprintln!("runner poll failed"),
        }
        if once { return; }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
