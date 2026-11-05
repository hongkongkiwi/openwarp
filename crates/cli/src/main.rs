use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::process::Command;

#[derive(Parser)] #[command(name = "openwarp", about = "OpenWarp secrets CLI (Phase-compatible workflow)")]
struct Cli { #[arg(long, env = "OPENWARP_HOST", default_value = "http://127.0.0.1:8080")] host: String, #[arg(long, env = "OPENWARP_TOKEN")] token: Option<String>, #[command(subcommand)] cmd: Cmd }
#[derive(Subcommand)] enum Cmd {
    /// Fetch secrets for an env: openwarp secrets --env <ENV_ID>
    Secrets { #[arg(long)] env: String, #[arg(long)] show: bool },
    /// Export as .env text
    Export { #[arg(long)] env: String },
    /// Import a .env file
    Import { #[arg(long)] env: String, file: String },
    /// Run a command with secrets injected: openwarp run --env <ID> -- <cmd...>
    Run { #[arg(long)] env: String, #[arg(last = true)] command: Vec<String> },
    /// Create an E2E environment (server never sees plaintext or env key)
    E2eCreate { #[arg(long)] app: String, #[arg(long)] name: String },
    /// Put a secret into an E2E env: needs OPENWARP_PRIVKEY (recovery kit)
    E2ePut { #[arg(long)] env: String, #[arg(long)] key: String, #[arg(long)] value: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    /// List/decrypt secrets from an E2E env locally
    E2eGet { #[arg(long)] env: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    /// Grant E2E env access to another user by email (re-wraps env key locally)
    E2eGrant { #[arg(long)] env: String, #[arg(long)] email: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
}

fn e2e_env_key(client: &reqwest::blocking::Client, host: &str, token: &str, env: &str, privkey: &str) -> ([u8;32], openwarp_crypto::Keypair) {
    let kp = openwarp_crypto::Keypair::from_secret_b64(privkey).expect("bad privkey (recovery kit)");
    let d: Value = client.get(format!("{}/api/envs/{}/e2e/secrets", host, env)).bearer_auth(token).send().expect("req").json().expect("json");
    let wrapped = d["wrapped_key"].as_str().unwrap_or_else(|| panic!("no wrapped key: {}", d));
    let raw = kp.decrypt(wrapped).expect("decrypt wrapped env key");
    (raw.try_into().expect("env key len"), kp)
}
fn main() {
    let cli = Cli::parse();
    let token = cli.token.clone().unwrap_or_default();
    let client = reqwest::blocking::Client::new();
    let get = |url: &str| -> Value { client.get(url).bearer_auth(&token).send().expect("request").json().expect("json") };
    match &cli.cmd {
        Cmd::Secrets { env, show } => { let d = get(&format!("{}/api/envs/{}/secrets", cli.host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { println!("{}={}", s["key"].as_str().unwrap_or(""), if *show { s["value"].as_str().unwrap_or("") } else { "[REDACTED]" }); } }
        Cmd::Export { env } => { let d = get(&format!("{}/api/envs/{}/export", cli.host, env)); println!("{}", d["text"].as_str().unwrap_or("")); }
        Cmd::Import { env, file } => { let text = std::fs::read_to_string(file).expect("read file");
            let d: Value = client.post(format!("{}/api/envs/{}/import", cli.host, env)).bearer_auth(&token).json(&json!({"text": text})).send().expect("request").json().expect("json"); println!("{}", d); }
        Cmd::Run { env, command } => { if command.is_empty() { eprintln!("usage: openwarp run --env <ID> -- <cmd...>"); std::process::exit(2); }
            let d = get(&format!("{}/api/envs/{}/export", cli.host, env));
            let mut cmd = Command::new(&command[0]); cmd.args(&command[1..]);
            for line in d["text"].as_str().unwrap_or("").lines() { if let Some((k, v)) = line.split_once('=') { cmd.env(k, v); } }
            std::process::exit(cmd.status().expect("spawn").code().unwrap_or(1)); }
        Cmd::E2eCreate { app, name } => { let d: Value = client.post(format!("{}/api/apps/{}/envs/e2e", cli.host, app)).bearer_auth(&token).json(&json!({"name": name})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2ePut { env, key, value, privkey } => { let (ek, _) = e2e_env_key(&client, &cli.host, &token, env, privkey);
            let kname = key.to_uppercase(); let khash = openwarp_crypto::hash_token(&format!("/:{}", kname));
            let payload = json!({"secrets": [{"key_enc": openwarp_crypto::encrypt_symmetric(&ek, kname.as_bytes()), "value_enc": openwarp_crypto::encrypt_symmetric(&ek, value.as_bytes()), "key_hash": khash, "path": "/"}]});
            let d: Value = client.put(format!("{}/api/envs/{}/e2e/secrets", cli.host, env)).bearer_auth(&token).json(&payload).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2eGet { env, privkey } => { let (ek, _) = e2e_env_key(&client, &cli.host, &token, env, privkey);
            let d = get(&format!("{}/api/envs/{}/e2e/secrets", cli.host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { let k = openwarp_crypto::decrypt_symmetric(&ek, s["key_enc"].as_str().unwrap_or("")).unwrap(); let v = openwarp_crypto::decrypt_symmetric(&ek, s["value_enc"].as_str().unwrap_or("")).unwrap(); println!("{}={}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v)); } }
        Cmd::E2eGrant { env, email, privkey } => { let (ek, _) = e2e_env_key(&client, &cli.host, &token, env, privkey);
            let u = get(&format!("{}/api/users/lookup?email={}", cli.host, email));
            let wrapped = openwarp_crypto::encrypt_to(u["pubkey"].as_str().expect("grantee pubkey"), &ek).expect("wrap");
            let d: Value = client.post(format!("{}/api/envs/{}/e2e/grant", cli.host, env)).bearer_auth(&token).json(&json!({"email": email, "wrapped_key": wrapped})).send().expect("req").json().expect("json"); println!("{}", d); }
    }
}
