use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::Command;

#[derive(Parser)] #[command(name = "openwarp", about = "OpenWarp secrets CLI")]
struct Cli { #[arg(long, env = "OPENWARP_HOST")] host: Option<String>, #[arg(long, env = "OPENWARP_TOKEN")] token: Option<String>, #[command(subcommand)] cmd: Cmd }
#[derive(Subcommand)] enum Cmd {
    /// Login: browser OAuth (default), --token <TOKEN>, or --client-id/--client-secret for machines
    Login { #[arg(long)] token: Option<String>, #[arg(long)] client_id: Option<String>, #[arg(long)] client_secret: Option<String> },
    Logout,
    Whoami,
    /// Write .openwarp.json with app/env defaults for this directory
    Init { #[arg(long)] app: String, #[arg(long)] env: String },
    Orgs,
    Apps { #[arg(long)] org: String },
    Envs { #[arg(long)] app: String },
    Secrets { #[arg(long)] env: String, #[arg(long)] show: bool },
    Get { #[arg(long)] env: String, key: String },
    Set { #[arg(long)] env: String, key: String, value: String },
    Delete { #[arg(long)] env: String, key: String },
    Export { #[arg(long)] env: String, #[arg(long, default_value = "dotenv")] format: String },
    Import { #[arg(long)] env: String, file: String },
    Run { #[arg(long)] env: String, #[arg(last = true)] command: Vec<String> },
    E2eCreate { #[arg(long)] app: String, #[arg(long)] name: String },
    E2ePut { #[arg(long)] env: String, #[arg(long)] key: String, #[arg(long)] value: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    E2eGet { #[arg(long)] env: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    E2eGrant { #[arg(long)] env: String, #[arg(long)] email: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    /// Print shell completions: openwarp completion bash|zsh|fish
    Completion { shell: String },
}

fn config_path() -> std::path::PathBuf { let home = std::env::var("HOME").unwrap_or_else(|_| ".".into()); std::path::Path::new(&home).join(".openwarp").join("config.json") }
fn load_config() -> Value { std::fs::read_to_string(config_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({})) }
fn save_config(v: &Value) { let p = config_path(); if let Some(parent) = p.parent() { let _ = std::fs::create_dir_all(parent); }
    std::fs::write(&p, serde_json::to_string_pretty(v).unwrap()).expect("write config");
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)); } }
fn b64url(data: &[u8]) -> String { use base64ct::{Base64UrlUnpadded, Encoding}; Base64UrlUnpadded::encode_string(data) }

fn e2e_env_key(client: &reqwest::blocking::Client, host: &str, token: &str, env: &str, privkey: &str) -> ([u8;32], openwarp_crypto::Keypair) {
    let kp = openwarp_crypto::Keypair::from_secret_b64(privkey).expect("bad privkey (recovery kit)");
    let d: Value = client.get(format!("{}/api/envs/{}/e2e/secrets", host, env)).bearer_auth(token).send().expect("req").json().expect("json");
    let wrapped = d["wrapped_key"].as_str().unwrap_or_else(|| panic!("no wrapped key: {}", d));
    let raw = kp.decrypt(wrapped).expect("decrypt wrapped env key");
    (raw.try_into().expect("env key len"), kp)
}

fn main() {
    let cli = Cli::parse();
    let cfg = load_config();
    let host = cli.host.clone().or_else(|| cfg["host"].as_str().map(|s| s.to_string())).unwrap_or_else(|| "http://127.0.0.1:8080".into());
    let token = cli.token.clone().or_else(|| cfg["access_token"].as_str().map(|s| s.to_string())).unwrap_or_default();
    let client = reqwest::blocking::Client::new();
    let get = |url: &str| -> Value { client.get(url).bearer_auth(&token).send().expect("request").error_for_status().unwrap_or_else(|e| panic!("GET {} failed: {} (are you logged in? run: openwarp login)", url, e)).json().expect("json") };
    let post = |url: &str, body: Value| -> Value { client.post(url).bearer_auth(&token).json(&body).send().expect("request").json().expect("json") };
    match &cli.cmd {
        Cmd::Login { token: t, client_id, client_secret } => {
            if let Some(tok) = t { let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(tok); save_config(&c); println!("Token saved to {}", config_path().display()); return; }
            if let (Some(cid), Some(sec)) = (client_id, client_secret) {
                let d: Value = client.post(format!("{}/api/v1/machine/auth/universal/login", host)).json(&json!({"client_id": cid, "client_secret": sec})).send().expect("req").json().expect("json");
                let at = d["accessToken"].as_str().unwrap_or_else(|| panic!("machine login failed: {}", d));
                let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(at); save_config(&c); println!("Machine login OK (token expires in {}s)", d["expiresIn"]); return; }
            // Browser OAuth 2.1 with PKCE, loopback redirect
            let reg: Value = client.post(format!("{}/oauth/register", host)).json(&json!({"client_name":"openwarp-cli","redirect_uris":["http://127.0.0.1:8917/callback"],"token_endpoint_auth_method":"none","scope":"secrets:read secrets:write mcp"})).send().expect("req").json().expect("json");
            let cid = reg["client_id"].as_str().expect("client_id").to_string();
            let verifier = openwarp_crypto::random_token("verifier");
            let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
            let state = openwarp_crypto::random_token("state");
            let url = format!("{}/oauth/authorize?response_type=code&client_id={}&redirect_uri=http%3A%2F%2F127.0.0.1%3A8917%2Fcallback&scope=secrets%3Aread%20secrets%3Awrite%20mcp&state={}&code_challenge={}&code_challenge_method=S256&resource={}%2Fmcp", host, cid, state, challenge, host);
            let listener = std::net::TcpListener::bind("127.0.0.1:8917").expect("bind loopback (close any other openwarp login waiting on this port)");
            println!("Open this URL to sign in and approve:\n{}", url);
            let _ = Command::new(if cfg!(target_os = "macos") { "open" } else { "xdg-open" }).arg(&url).status();
            let (mut stream, _) = listener.accept().expect("callback");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
            let mut request_line = String::new(); { use std::io::BufRead; let _ = reader.read_line(&mut request_line); let mut line = String::new(); loop { line.clear(); match reader.read_line(&mut line) { Ok(0) => break, Ok(_) if line == "\r\n" || line == "\n" => break, Ok(_) => continue, Err(_) => break } } }
            let body = "<h1>OpenWarp login complete. Return to your terminal.</h1>";
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Both);
            let query = request_line.split_whitespace().nth(1).unwrap_or("").to_string();
            let query = query.as_str();
            let params: std::collections::HashMap<String, String> = query.split('?').nth(1).unwrap_or("").split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
            if params.get("state").map(|s| s.as_str()) != Some(&state) { panic!("OAuth state mismatch"); }
            let code = params.get("code").expect("no code in callback").clone();
            let form = [("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", "http://127.0.0.1:8917/callback"), ("client_id", &cid), ("code_verifier", &verifier)];
            let tok: Value = client.post(format!("{}/oauth/token", host)).form(&form).send().expect("req").json().expect("json");
            let at = tok["access_token"].as_str().unwrap_or_else(|| panic!("token exchange failed: {}", tok));
            let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(at); c["refresh_token"] = tok["refresh_token"].clone(); c["client_id"] = json!(cid); save_config(&c);
            println!("Logged in. Credentials saved to {}", config_path().display());
        }
        Cmd::Logout => { let _ = client.post(format!("{}/api/auth/logout", host)).bearer_auth(&token).send(); let mut c = cfg.clone(); c["access_token"] = Value::Null; c["refresh_token"] = Value::Null; save_config(&c); println!("Logged out"); }
        Cmd::Whoami => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/me", host))).unwrap()); }
        Cmd::Init { app, env } => { std::fs::write(".openwarp.json", serde_json::to_string_pretty(&json!({"host": host, "app_id": app, "env_id": env})).unwrap()).expect("write .openwarp.json"); println!("Wrote .openwarp.json"); }
        Cmd::Orgs => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/orgs", host))).unwrap()); }
        Cmd::Apps { org } => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/orgs/{}/apps", host, org))).unwrap()); }
        Cmd::Envs { app } => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/apps/{}/envs", host, app))).unwrap()); }
        Cmd::Secrets { env, show } => { let d = get(&format!("{}/api/envs/{}/secrets", host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { println!("{}={}", s["key"].as_str().unwrap_or(""), if *show { s["value"].as_str().unwrap_or("") } else { "[REDACTED]" }); } }
        Cmd::Get { env, key } => { let d = get(&format!("{}/api/envs/{}/secrets", host, env));
            match d["secrets"].as_array().and_then(|a| a.iter().find(|s| s["key"].as_str() == Some(&key.to_uppercase()))) { Some(s) => println!("{}", s["value"].as_str().unwrap_or("")), None => { eprintln!("secret not found: {}", key); std::process::exit(1); } } }
        Cmd::Set { env, key, value } => { let d: Value = client.put(format!("{}/api/envs/{}/secrets", host, env)).bearer_auth(&token).json(&json!({"secrets": [{"key": key, "value": value}]})).send().expect("req").json().expect("json"); let _ = &post;
            println!("{}", if d.get("deployed").is_some() { format!("Set {} (deployed {})", key.to_uppercase(), d["deployed"]) } else { d.to_string() }); }
        Cmd::Delete { env, key } => { let d = get(&format!("{}/api/envs/{}/secrets", host, env));
            let sid = d["secrets"].as_array().and_then(|a| a.iter().find(|s| s["key"].as_str() == Some(&key.to_uppercase()))).and_then(|s| s["id"].as_str().map(|x| x.to_string()));
            match sid { Some(id) => { let r: Value = client.delete(format!("{}/api/secrets/{}", host, id)).bearer_auth(&token).send().expect("req").json().expect("json"); println!("{}", r); } None => { eprintln!("secret not found: {}", key); std::process::exit(1); } } }
        Cmd::Export { env, format } => { let d = get(&format!("{}/api/envs/{}/export", host, env));
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&d["secrets"]).unwrap()),
                "yaml" => { for s in d["secrets"].as_array().cloned().unwrap_or_default() { println!("{}: {:?}", s["key"].as_str().unwrap_or(""), s["value"].as_str().unwrap_or("")); } }
                "shell" => { for line in d["text"].as_str().unwrap_or("").lines() { if let Some((k, v)) = line.split_once('=') { println!("export {}='{}'", k, v.replace('\'', "'\\''")); } } }
                _ => println!("{}", d["text"].as_str().unwrap_or("")), } }
        Cmd::Import { env, file } => { let text = std::fs::read_to_string(file).expect("read file");
            let d: Value = client.post(format!("{}/api/envs/{}/import", host, env)).bearer_auth(&token).json(&json!({"text": text})).send().expect("request").json().expect("json"); println!("{}", d); }
        Cmd::Run { env, command } => { if command.is_empty() { eprintln!("usage: openwarp run --env <ID> -- <cmd...>"); std::process::exit(2); }
            let d = get(&format!("{}/api/envs/{}/export", host, env));
            let mut cmd = Command::new(&command[0]); cmd.args(&command[1..]);
            for line in d["text"].as_str().unwrap_or("").lines() { if let Some((k, v)) = line.split_once('=') { cmd.env(k, v); } }
            std::process::exit(cmd.status().expect("spawn").code().unwrap_or(1)); }
        Cmd::E2eCreate { app, name } => { let d: Value = client.post(format!("{}/api/apps/{}/envs/e2e", host, app)).bearer_auth(&token).json(&json!({"name": name})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2ePut { env, key, value, privkey } => { let (ek, _) = e2e_env_key(&client, &host, &token, env, privkey);
            let kname = key.to_uppercase(); let khash = openwarp_crypto::hash_token(&format!("/:{}", kname));
            let payload = json!({"secrets": [{"key_enc": openwarp_crypto::encrypt_symmetric(&ek, kname.as_bytes()), "value_enc": openwarp_crypto::encrypt_symmetric(&ek, value.as_bytes()), "key_hash": khash, "path": "/"}]});
            let d: Value = client.put(format!("{}/api/envs/{}/e2e/secrets", host, env)).bearer_auth(&token).json(&payload).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2eGet { env, privkey } => { let (ek, _) = e2e_env_key(&client, &host, &token, env, privkey);
            let d = get(&format!("{}/api/envs/{}/e2e/secrets", host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { let k = openwarp_crypto::decrypt_symmetric(&ek, s["key_enc"].as_str().unwrap_or("")).unwrap(); let v = openwarp_crypto::decrypt_symmetric(&ek, s["value_enc"].as_str().unwrap_or("")).unwrap(); println!("{}={}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v)); } }
        Cmd::E2eGrant { env, email, privkey } => { let (ek, _) = e2e_env_key(&client, &host, &token, env, privkey);
            let u = get(&format!("{}/api/users/lookup?email={}", host, email));
            let wrapped = openwarp_crypto::encrypt_to(u["pubkey"].as_str().expect("grantee pubkey"), &ek).expect("wrap");
            let d: Value = client.post(format!("{}/api/envs/{}/e2e/grant", host, env)).bearer_auth(&token).json(&json!({"email": email, "wrapped_key": wrapped})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::Completion { shell } => { use clap::CommandFactory; let mut cmd = Cli::command(); let sh = match shell.as_str() { "zsh" => clap_complete::Shell::Zsh, "fish" => clap_complete::Shell::Fish, "powershell" => clap_complete::Shell::PowerShell, _ => clap_complete::Shell::Bash }; clap_complete::generate(sh, &mut cmd, "openwarp", &mut std::io::stdout()); }
    }
}
