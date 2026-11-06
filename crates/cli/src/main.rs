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
    Envs { #[arg(long, default_value = "")] app: String },
    Secrets { #[arg(long, default_value = "")] env: String, #[arg(long)] show: bool },
    Get { #[arg(long, default_value = "")] env: String, key: String },
    Set { #[arg(long, default_value = "")] env: String, key: String, value: String },
    Delete { #[arg(long, default_value = "")] env: String, key: String },
    Export { #[arg(long, default_value = "")] env: String, #[arg(long, default_value = "dotenv")] format: String },
    Import { #[arg(long, default_value = "")] env: String, file: String },
    Run { #[arg(long, default_value = "")] env: String, #[arg(last = true)] command: Vec<String> },
    E2eCreate { #[arg(long, default_value = "")] app: String, #[arg(long)] name: String,
        /// Create a delegated environment owned by a customer-run sync runner
        #[arg(long)] delegated: bool,
        #[arg(long, default_value = "", env = "OPENWARP_RUNNER_ID")] runner_id: String,
        #[arg(long, default_value = "", env = "OPENWARP_RUNNER_PUBKEY")] runner_pubkey: String },
    E2ePut { #[arg(long, default_value = "")] env: String, #[arg(long)] key: String, #[arg(long)] value: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    E2eGet { #[arg(long, default_value = "")] env: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    E2eGrant { #[arg(long, default_value = "")] env: String, #[arg(long)] email: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    /// Rotate a client-encrypted environment key and rewrap it to every current grantee
    E2eRekey { #[arg(long, default_value = "")] env: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    /// Create a customer-run sync runner; prints its token and private key once
    RunnerCreate { #[arg(long)] org: String, #[arg(long, default_value = "runner")] name: String },
    /// Print shell completions: openwarp completion bash|zsh|fish
    Completion { shell: String },
}

fn config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("OPENWARP_CONFIG") { if !p.is_empty() { return std::path::PathBuf::from(p); } }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into()); std::path::Path::new(&home).join(".openwarp").join("config.json") }

// Access and refresh tokens go to the operating system's credential store when
// one is available; the 0600 config file keeps only non-secret settings. Set
// OPENWARP_NO_KEYRING=1 to force the file-only behaviour.
const KEYRING_SERVICE: &str = "openwarp";
fn keyring_enabled() -> bool {
    if std::env::var("OPENWARP_NO_KEYRING").map(|v| v == "1").unwrap_or(false) { return false; }
    cfg!(any(target_os = "macos", target_os = "linux")) }
#[cfg(target_os = "macos")]
fn keyring_set_raw(account: &str, value: &str) -> bool {
    std::process::Command::new("security")
        .args(["add-generic-password", "-U", "-s", KEYRING_SERVICE, "-a", account, "-w", value])
        .output().map(|o| o.status.success()).unwrap_or(false) }
#[cfg(target_os = "linux")]
fn keyring_set_raw(account: &str, value: &str) -> bool {
    use std::io::Write; use std::process::Stdio;
    let mut child = match std::process::Command::new("secret-tool")
        .args(["store", "--label", KEYRING_SERVICE, "service", KEYRING_SERVICE, "host", account])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() { Ok(c) => c, Err(_) => return false };
    if let Some(mut stdin) = child.stdin.take() { let _ = stdin.write_all(value.as_bytes()); }
    child.wait().map(|s| s.success()).unwrap_or(false) }
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keyring_set_raw(_account: &str, _value: &str) -> bool { false }
#[cfg(target_os = "macos")]
fn keyring_get_raw(account: &str) -> Option<String> {
    let out = std::process::Command::new("security").args(["find-generic-password", "-s", KEYRING_SERVICE, "-a", account, "-w"]).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } }
#[cfg(target_os = "linux")]
fn keyring_get_raw(account: &str) -> Option<String> {
    let out = std::process::Command::new("secret-tool").args(["lookup", "service", KEYRING_SERVICE, "host", account]).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } }
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keyring_get_raw(_account: &str) -> Option<String> { None }
#[cfg(target_os = "macos")]
fn keyring_del_raw(account: &str) { let _ = std::process::Command::new("security").args(["delete-generic-password", "-s", KEYRING_SERVICE, "-a", account]).output(); }
#[cfg(target_os = "linux")]
fn keyring_del_raw(account: &str) { let _ = std::process::Command::new("secret-tool").args(["clear", "service", KEYRING_SERVICE, "host", account]).output(); }
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keyring_del_raw(_account: &str) {}
fn keyring_account(host: &str, kind: &str) -> String { format!("{}:{}", host, kind) }
fn keyring_store(host: &str, kind: &str, value: &str) -> bool {
    if !keyring_enabled() || value.is_empty() { return false; }
    keyring_set_raw(&keyring_account(host, kind), value) }
fn keyring_get(host: &str, kind: &str) -> Option<String> {
    if !keyring_enabled() { return None; }
    keyring_get_raw(&keyring_account(host, kind)) }
fn keyring_delete(host: &str, kind: &str) { if keyring_enabled() { keyring_del_raw(&keyring_account(host, kind)); } }

fn load_config() -> Value {
    let mut v = std::fs::read_to_string(config_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
    if let Some(host) = v["host"].as_str().map(|s| s.to_string()) {
        for kind in ["access_token", "refresh_token"] {
            if v[kind].as_str().map(|s| s.is_empty()).unwrap_or(true) {
                if let Some(tok) = keyring_get(&host, kind) { v[kind] = json!(tok); } } } }
    v }
fn save_config(v: &Value) {
    let p = config_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)); }
    }
    // Move secrets into the keyring first; only remove them from the file for
    // the entries the keyring actually accepted.
    let mut stored = v.clone();
    if let Some(host) = v["host"].as_str().map(|s| s.to_string()) {
        for kind in ["access_token", "refresh_token"] {
            match v[kind].as_str() { Some(tok) if !tok.is_empty() => { if keyring_store(&host, kind, tok) { stored[kind] = Value::Null; } }
                _ => keyring_delete(&host, kind) } } }
    let data = serde_json::to_string_pretty(&stored).expect("serialize config");
    #[cfg(unix)] {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&p).expect("write config");
        f.write_all(data.as_bytes()).expect("write config");
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))] { std::fs::write(&p, data).expect("write config"); }
}
fn b64url(data: &[u8]) -> String { use base64ct::{Base64UrlUnpadded, Encoding}; Base64UrlUnpadded::encode_string(data) }
fn urlq(s: &str) -> String { s.bytes().map(|b| match b { b'A'..=b'Z'|b'a'..=b'z'|b'0'..=b'9'|b'-'|b'_'|b'.'|b'~' => (b as char).to_string(), _ => format!("%{:02X}", b) }).collect() }
fn load_local_config() -> Value { std::fs::read_to_string(".openwarp.json").ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({})) }
fn pick(explicit: &str, local: &Value, key: &str, flag: &str) -> String {
    if !explicit.is_empty() { return explicit.to_string(); }
    if let Some(v) = local[key].as_str() { if !v.is_empty() { return v.to_string(); } }
    eprintln!("no value for {}: pass the flag or run openwarp init --app <APP_ID> --env <ENV_ID>", flag);
    std::process::exit(2) }
fn now_secs() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
// A dotenv value with whitespace or quotes must stay on one line; encode the
// characters that would otherwise break the file.
fn dotenv_value(v: &str) -> String {
    if v.is_empty() || v.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '\\' || c == '#') {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r"))
    } else { v.to_string() }
}
fn token_expired(cfg: &Value) -> bool {
    let has_refresh = cfg["refresh_token"].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    if !has_refresh { return false; }
    let at = cfg["obtained_at"].as_i64().unwrap_or(0);
    at == 0 || now_secs() - at > 3000 }
fn refresh_lock() -> Option<std::path::PathBuf> {
    let p = config_path().with_file_name("config.lock");
    for _ in 0..2 {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(_) => return Some(p),
            Err(_) => { let stale = std::fs::metadata(&p).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).map(|d| d.as_secs() > 30).unwrap_or(false);
                if stale { let _ = std::fs::remove_file(&p); continue; } return None; }
        }
    }
    None }
fn refresh_tokens(client: &reqwest::blocking::Client, host: &str, cfg: &Value) -> Option<(String, String)> {
    let rt = cfg["refresh_token"].as_str()?; let cid = cfg["client_id"].as_str()?;
    let d: Value = client.post(format!("{}/oauth/token", host)).form(&[("grant_type", "refresh_token"), ("refresh_token", rt), ("client_id", cid)]).send().ok()?.json().ok()?;
    Some((d["access_token"].as_str()?.to_string(), d["refresh_token"].as_str().unwrap_or(rt).to_string())) }

fn e2e_env_key(client: &reqwest::blocking::Client, host: &str, token: &str, env: &str, privkey: &str) -> ([u8;32], openwarp_crypto::Keypair) {
    let kp = openwarp_crypto::Keypair::from_secret_b64(privkey).expect("bad privkey (recovery kit)");
    let d: Value = client.get(format!("{}/api/envs/{}/e2e/secrets", host, env)).bearer_auth(token).send().expect("req").json().expect("json");
    let wrapped = d["wrapped_key"].as_str().unwrap_or_else(|| panic!("no wrapped key: {}", d));
    let raw = kp.decrypt(wrapped).expect("decrypt wrapped env key");
    (raw.try_into().expect("env key len"), kp)
}

fn main() {
    let cli = Cli::parse();
    let local = load_local_config();
    let mut cfg = load_config();
    let host = cli.host.clone().or_else(|| cfg["host"].as_str().map(|s| s.to_string())).or_else(|| local["host"].as_str().map(|s| s.to_string())).unwrap_or_else(|| "http://127.0.0.1:8080".into());
    let client = reqwest::blocking::Client::new();
    let saved_host = cfg["host"].as_str().map(|s| s.to_string());
    if cli.token.is_none() && saved_host.as_deref() == Some(host.as_str()) && token_expired(&cfg) {
        match refresh_lock() {
            Some(lock) => {
                let fresh = load_config();
                if token_expired(&fresh) {
                    if let Some((at, rt)) = refresh_tokens(&client, &host, &fresh) { let mut c = fresh.clone(); c["access_token"] = json!(at); c["refresh_token"] = json!(rt); c["obtained_at"] = json!(now_secs()); save_config(&c); cfg = c; }
                } else { cfg = fresh; }
                let _ = std::fs::remove_file(lock);
            }
            None => { std::thread::sleep(std::time::Duration::from_millis(300)); if let Ok(s) = std::fs::read_to_string(config_path()) { if let Ok(v) = serde_json::from_str::<Value>(&s) { cfg = v; } } }
        }
    }
    let token = cli.token.clone().or_else(|| cfg["access_token"].as_str().map(|s| s.to_string())).unwrap_or_default();
    let get = |url: &str| -> Value { client.get(url).bearer_auth(&token).send().expect("request").error_for_status().unwrap_or_else(|e| panic!("GET {} failed: {} (are you logged in? run: openwarp login)", url, e)).json().expect("json") };
    let post = |url: &str, body: Value| -> Value { client.post(url).bearer_auth(&token).json(&body).send().expect("request").json().expect("json") };
    match &cli.cmd {
        Cmd::Login { token: t, client_id, client_secret } => {
            if let Some(tok) = t { let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(tok); c["refresh_token"] = Value::Null; c["client_id"] = Value::Null; c["obtained_at"] = json!(now_secs()); save_config(&c); println!("Token saved to {}", config_path().display()); return; }
            if let (Some(cid), Some(sec)) = (client_id, client_secret) {
                let d: Value = client.post(format!("{}/api/v1/machine/auth/universal/login", host)).json(&json!({"client_id": cid, "client_secret": sec})).send().expect("req").json().expect("json");
                let at = d["accessToken"].as_str().unwrap_or_else(|| panic!("machine login failed: {}", d));
                let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(at); c["refresh_token"] = Value::Null; c["client_id"] = Value::Null; c["obtained_at"] = json!(now_secs()); save_config(&c); println!("Machine login OK (token expires in {}s)", d["expiresIn"]); return; }
            // Browser OAuth 2.1 with PKCE, loopback redirect on an ephemeral port
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port for the OAuth redirect");
            let port = listener.local_addr().expect("loopback address").port();
            let redirect = format!("http://127.0.0.1:{}/callback", port);
            let encoded = redirect.replace(':', "%3A").replace('/', "%2F");
            let reg: Value = client.post(format!("{}/oauth/register", host)).json(&json!({"client_name":"openwarp-cli","redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":"secrets:read secrets:write mcp"})).send().expect("req").json().expect("json");
            let cid = reg["client_id"].as_str().expect("client_id").to_string();
            let verifier = openwarp_crypto::random_token("verifier");
            let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
            let state = openwarp_crypto::random_token("state");
            let url = format!("{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=secrets%3Aread%20secrets%3Awrite%20mcp&state={}&code_challenge={}&code_challenge_method=S256&resource={}%2Fmcp", host, cid, encoded, state, challenge, host);
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
            let form = [("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", redirect.as_str()), ("client_id", &cid), ("code_verifier", &verifier)];
            let tok: Value = client.post(format!("{}/oauth/token", host)).form(&form).send().expect("req").json().expect("json");
            let at = tok["access_token"].as_str().unwrap_or_else(|| panic!("token exchange failed: {}", tok));
            let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(at); c["refresh_token"] = tok["refresh_token"].clone(); c["client_id"] = json!(cid); c["obtained_at"] = json!(now_secs()); save_config(&c);
            println!("Logged in. Credentials saved to {}", config_path().display());
        }
        Cmd::Logout => { let _ = client.post(format!("{}/api/auth/logout", host)).bearer_auth(&token).send(); let mut c = cfg.clone(); c["access_token"] = Value::Null; c["refresh_token"] = Value::Null; c["client_id"] = Value::Null; save_config(&c); println!("Logged out"); }
        Cmd::Whoami => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/me", host))).unwrap()); }
        Cmd::Init { app, env } => { std::fs::write(".openwarp.json", serde_json::to_string_pretty(&json!({"host": host, "app_id": app, "env_id": env})).unwrap()).expect("write .openwarp.json"); println!("Wrote .openwarp.json"); }
        Cmd::Orgs => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/orgs", host))).unwrap()); }
        Cmd::Apps { org } => { println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/orgs/{}/apps", host, org))).unwrap()); }
        Cmd::Envs { app } => { let app = pick(app, &local, "app_id", "--app"); println!("{}", serde_json::to_string_pretty(&get(&format!("{}/api/apps/{}/envs", host, app))).unwrap()); }
        Cmd::Secrets { env, show } => { let env = pick(env, &local, "env_id", "--env"); let d = get(&format!("{}/api/envs/{}/secrets", host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { println!("{}={}", s["key"].as_str().unwrap_or(""), if *show { s["value"].as_str().unwrap_or("") } else { "[REDACTED]" }); } }
        Cmd::Get { env, key } => { let env = pick(env, &local, "env_id", "--env"); let d = get(&format!("{}/api/envs/{}/secrets", host, env));
            match d["secrets"].as_array().and_then(|a| a.iter().find(|s| s["key"].as_str() == Some(&key.to_uppercase()))) { Some(s) => println!("{}", s["value"].as_str().unwrap_or("")), None => { eprintln!("secret not found: {}", key); std::process::exit(1); } } }
        Cmd::Set { env, key, value } => { let env = pick(env, &local, "env_id", "--env"); let d: Value = client.put(format!("{}/api/envs/{}/secrets", host, env)).bearer_auth(&token).json(&json!({"secrets": [{"key": key, "value": value}]})).send().expect("req").json().expect("json"); let _ = &post;
            println!("{}", if d.get("deployed").is_some() { format!("Set {} (deployed {})", key.to_uppercase(), d["deployed"]) } else { d.to_string() }); }
        Cmd::Delete { env, key } => { let env = pick(env, &local, "env_id", "--env"); let d = get(&format!("{}/api/envs/{}/secrets", host, env));
            let sid = d["secrets"].as_array().and_then(|a| a.iter().find(|s| s["key"].as_str() == Some(&key.to_uppercase()))).and_then(|s| s["id"].as_str().map(|x| x.to_string()));
            match sid { Some(id) => { let r: Value = client.delete(format!("{}/api/secrets/{}", host, id)).bearer_auth(&token).send().expect("req").json().expect("json"); println!("{}", r); } None => { eprintln!("secret not found: {}", key); std::process::exit(1); } } }
        Cmd::Export { env, format } => { let env = pick(env, &local, "env_id", "--env"); let d = get(&format!("{}/api/envs/{}/export", host, env));
            let items = d["secrets"].as_array().cloned().unwrap_or_default();
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&d["secrets"]).unwrap()),
                "yaml" => { for s in &items { println!("{}: {}", s["key"].as_str().unwrap_or(""), serde_json::to_string(s["value"].as_str().unwrap_or("")).unwrap()); } }
                "shell" => { for s in &items { let v = s["value"].as_str().unwrap_or(""); println!("export {}='{}'", s["key"].as_str().unwrap_or(""), v.replace('\'', "'\\''")); } }
                _ => { for s in &items { println!("{}={}", s["key"].as_str().unwrap_or(""), dotenv_value(s["value"].as_str().unwrap_or(""))); } } } }
        Cmd::Import { env, file } => { let env = pick(env, &local, "env_id", "--env"); let text = std::fs::read_to_string(file).expect("read file");
            let d: Value = client.post(format!("{}/api/envs/{}/import", host, env)).bearer_auth(&token).json(&json!({"text": text})).send().expect("request").json().expect("json"); println!("{}", d); }
        Cmd::Run { env, command } => { let env = pick(env, &local, "env_id", "--env"); if command.is_empty() { eprintln!("usage: openwarp run --env <ID> -- <cmd...>"); std::process::exit(2); }
            let d = get(&format!("{}/api/envs/{}/export", host, env));
            let mut cmd = Command::new(&command[0]); cmd.args(&command[1..]);
            for s in d["secrets"].as_array().cloned().unwrap_or_default() {
                if let (Some(k), Some(v)) = (s["key"].as_str(), s["value"].as_str()) { cmd.env(k, v); }
            }
            std::process::exit(cmd.status().expect("spawn").code().unwrap_or(1)); }
        Cmd::E2eCreate { app, name, delegated, runner_id, runner_pubkey } => { let app = pick(app, &local, "app_id", "--app");
            let me = get(&format!("{}/api/me", host));
            let env_key = openwarp_crypto::random_key();
            let wrapped = openwarp_crypto::encrypt_to(me["pubkey"].as_str().expect("public key"), &env_key).expect("wrap env key");
            if *delegated {
                if runner_id.is_empty() || runner_pubkey.is_empty() { eprintln!("--delegated needs --runner-id and --runner-pubkey (or OPENWARP_RUNNER_ID / OPENWARP_RUNNER_PUBKEY)"); std::process::exit(2); }
                let runner_wrapped = openwarp_crypto::encrypt_to(runner_pubkey, &env_key).expect("wrap runner env key");
                let d: Value = client.post(format!("{}/api/apps/{}/envs", host, app)).bearer_auth(&token)
                    .json(&json!({"name": name, "mode": "delegated", "runner_id": runner_id, "wrapped_key": wrapped, "runner_wrapped_key": runner_wrapped}))
                    .send().expect("req").json().expect("json"); println!("{}", d); return; }
            let d: Value = client.post(format!("{}/api/apps/{}/envs/e2e", host, app)).bearer_auth(&token).json(&json!({"name": name, "wrapped_key": wrapped})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2ePut { env, key, value, privkey } => { let env = pick(env, &local, "env_id", "--env"); let (ek, _) = e2e_env_key(&client, &host, &token, &env, privkey);
            let kname = key.to_uppercase(); let khash = openwarp_crypto::hash_token(&format!("/:{}", kname));
            let payload = json!({"secrets": [{"key_enc": openwarp_crypto::encrypt_symmetric(&ek, kname.as_bytes()), "value_enc": openwarp_crypto::encrypt_symmetric(&ek, value.as_bytes()), "key_hash": khash, "path": "/"}]});
            let d: Value = client.put(format!("{}/api/envs/{}/e2e/secrets", host, env)).bearer_auth(&token).json(&payload).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2eGet { env, privkey } => { let env = pick(env, &local, "env_id", "--env"); let (ek, _) = e2e_env_key(&client, &host, &token, &env, privkey);
            let d = get(&format!("{}/api/envs/{}/e2e/secrets", host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { let k = openwarp_crypto::decrypt_symmetric(&ek, s["key_enc"].as_str().unwrap_or("")).unwrap(); let v = openwarp_crypto::decrypt_symmetric(&ek, s["value_enc"].as_str().unwrap_or("")).unwrap(); println!("{}={}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v)); } }
        Cmd::E2eGrant { env, email, privkey } => { let env = pick(env, &local, "env_id", "--env"); let (ek, _) = e2e_env_key(&client, &host, &token, &env, privkey);
            let u = get(&format!("{}/api/users/lookup?email={}", host, urlq(email)));
            let wrapped = openwarp_crypto::encrypt_to(u["pubkey"].as_str().expect("grantee pubkey"), &ek).expect("wrap");
            let d: Value = client.post(format!("{}/api/envs/{}/e2e/grant", host, env)).bearer_auth(&token).json(&json!({"email": email, "wrapped_key": wrapped})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2eRekey { env, privkey } => { let env = pick(env, &local, "env_id", "--env");
            let kp = openwarp_crypto::Keypair::from_secret_b64(privkey).expect("bad privkey (recovery kit)");
            let d = get(&format!("{}/api/envs/{}/e2e/secrets", host, env));
            let old: [u8;32] = kp.decrypt(d["wrapped_key"].as_str().expect("wrapped key")).expect("decrypt env key").try_into().expect("env key length");
            let new_key = openwarp_crypto::random_key();
            let mut items = Vec::new();
            for s in d["secrets"].as_array().cloned().unwrap_or_default() {
                let key = openwarp_crypto::decrypt_symmetric(&old, s["key_enc"].as_str().unwrap_or("")).expect("decrypt key");
                let value = openwarp_crypto::decrypt_symmetric(&old, s["value_enc"].as_str().unwrap_or("")).expect("decrypt value");
                items.push(json!({"key_enc": openwarp_crypto::encrypt_symmetric(&new_key, &key), "value_enc": openwarp_crypto::encrypt_symmetric(&new_key, &value), "key_hash": s["key_hash"].clone(), "path": s["path"].clone()}));
            }
            let existing = get(&format!("{}/api/envs/{}/e2e/grants", host, env));
            let mut grants = Vec::new();
            for g in existing.as_array().cloned().unwrap_or_default() {
                let uid = g["user_id"].as_str().unwrap_or(""); let email = g["email"].as_str().unwrap_or("");
                let pubkey = g["pubkey"].as_str().map(str::to_string).filter(|p| !p.is_empty()).unwrap_or_else(|| {
                    let u = get(&format!("{}/api/users/lookup?email={}", host, urlq(email)));
                    u["pubkey"].as_str().unwrap_or("").to_string()
                });
                let wrapped = openwarp_crypto::encrypt_to(&pubkey, &new_key).expect("wrap grant");
                grants.push(json!({"user_id": uid, "wrapped_key": wrapped}));
            }
            let meta = get(&format!("{}/api/envs/{}/e2e/meta", host, env));
            let mut body = json!({"secrets": items, "grants": grants});
            if let Some(pk) = meta["runner"]["public_key"].as_str() {
                body["runner_wrapped_key"] = json!(openwarp_crypto::encrypt_to(pk, &new_key).expect("wrap runner key"));
            }
            let d: Value = client.post(format!("{}/api/envs/{}/e2e/rekey", host, env)).bearer_auth(&token).json(&body).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::RunnerCreate { org, name } => { let kp = openwarp_crypto::Keypair::generate();
            let d: Value = client.post(format!("{}/api/orgs/{}/runners", host, org)).bearer_auth(&token).json(&json!({"name": name, "public_key": kp.public})).send().expect("req").json().expect("json");
            println!("runner_id: {}\nrunner_token: {}\nrunner_key: {}", d["id"].as_str().unwrap_or(""), d["token"].as_str().unwrap_or(""), kp.secret_b64()); }
        Cmd::Completion { shell } => { use clap::CommandFactory; let mut cmd = Cli::command(); let sh = match shell.as_str() { "zsh" => clap_complete::Shell::Zsh, "fish" => clap_complete::Shell::Fish, "powershell" => clap_complete::Shell::PowerShell, _ => clap_complete::Shell::Bash }; clap_complete::generate(sh, &mut cmd, "openwarp", &mut std::io::stdout()); }
    }
}
