//! Customer-run sync runner. It polls a delegated environment's jobs, unwraps
//! the environment key with its own X25519 key, decrypts provider config and
//! secret values in this process, and pushes them to the provider. The server
//! never receives plaintext or provider credentials.
use openwarp_crypto as oc;
use openwarp_server::integrations;
use serde_json::{json, Value};
use std::time::Duration;

fn env(name: &str) -> String { std::env::var(name).unwrap_or_default() }

async fn send(client: &reqwest::Client, base: &str, token: &str, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, String> {
    let mut req = client.request(method, format!("{}{}", base.trim_end_matches('/'), path)).bearer_auth(token);
    if let Some(b) = body { req = req.json(&b); }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if !status.is_success() { return Err(format!("HTTP {}: {}", status, text)); }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn decrypt_secret(env_key: &[u8;32], enc: &str) -> Result<String, String> {
    oc::decrypt_symmetric(env_key, enc).map(|b| String::from_utf8_lossy(&b).into_owned())
}

struct Prepared { config: Value, pairs: Vec<(String, String)> }
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
    let config = envelope.get("config").cloned().ok_or("sealed integration config has no config body")?;
    let mut pairs = Vec::new();
    for s in job.get("secrets").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let key = decrypt_secret(&env_key, s.get("key_enc").and_then(|v| v.as_str()).unwrap_or(""))?;
        let value = decrypt_secret(&env_key, s.get("value_enc").and_then(|v| v.as_str()).unwrap_or(""))?;
        pairs.push((key, value));
    }
    Ok(Prepared { config, pairs })
}

async fn run_sync(kind: &str, config: &Value, pairs: &[(String, String)], previous: &[String]) -> Result<(String, Vec<(String, String)>), String> {
    let (msg, managed) = match kind {
        "trigger" => integrations::trigger_sync(config, pairs, previous).await?,
        "instabox" => integrations::instabox_sync(config, pairs, previous).await?,
        "boat" => integrations::boat_sync(config, pairs, previous).await?,
        "daytona" => integrations::daytona_sync(config, pairs, previous).await?,
        _ => (integrations::sync(kind, config, pairs).await?, Vec::new()),
    };
    let prefix = config.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
    let hashed = managed.into_iter().map(|name| {
        let base = name.strip_prefix(prefix).unwrap_or(&name).to_string();
        let hash = pairs.iter().find(|(k, _)| k == &base).map(|(_, v)| oc::hash_token(v)).unwrap_or_default();
        (name, hash)
    }).collect();
    Ok((msg, hashed))
}

async fn run_test(kind: &str, config: &Value) -> Result<(String, Vec<(String, String)>), String> {
    let msg = match kind {
        "trigger" => integrations::trigger_test(config).await?,
        "instabox" => integrations::instabox_test(config).await?,
        "boat" => integrations::boat_test(config).await?,
        "daytona" => integrations::daytona_test(config).await?,
        _ => return Err(format!("connection test is not implemented for kind {}", kind)),
    };
    Ok((msg, Vec::new()))
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
    let kp = match oc::Keypair::from_secret_b64(&secret) { Ok(k) => k, Err(e) => { eprintln!("bad OPENWARP_RUNNER_KEY: {}", e); std::process::exit(2); } };
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
                            else {
                                let previous: Vec<String> = job.get("previous").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
                                run_sync(&kind, &p.config, &p.pairs, &previous).await
                            }
                        }
                        Err(e) => Err(e),
                    };
                    let claim = job.get("claim").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let body = match result {
                        Ok((detail, managed)) => {
                            let managed: Vec<Value> = managed.into_iter().map(|(name, value_hash)| json!({"name": name, "value_hash": value_hash})).collect();
                            json!({"ok": true, "detail": detail, "managed": managed, "claim": claim})
                        }
                        Err(e) => json!({"ok": false, "detail": e, "claim": claim}),
                    };
                    if let Err(e) = send(&client, &base, &token, reqwest::Method::POST, &format!("/api/runner/jobs/{}/result", jid), Some(body)).await {
                        eprintln!("could not report job {}: {}", jid, e);
                    }
                }
            }
            Err(e) => eprintln!("runner poll failed: {}", e),
        }
        if once { return; }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
