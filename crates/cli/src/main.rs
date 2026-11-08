use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)] #[command(name = "openwarp", about = "OpenWarp secrets CLI")]
struct Cli { #[arg(long, env = "OPENWARP_HOST")] host: Option<String>, #[arg(long, env = "OPENWARP_TOKEN")] token: Option<String>, #[command(subcommand)] cmd: Cmd }
#[derive(Subcommand)] enum Cmd {
    /// Login: browser OAuth (default), --token <TOKEN>, or --client-id/--client-secret for machines
    Login { #[arg(long)] token: Option<String>, #[arg(long)] client_id: Option<String>, #[arg(long)] client_secret: Option<String>, #[arg(long, default_value = "secrets:read secrets:write mcp")] scope: String },
    /// Call a same-origin /api route with the current credential
    Api { method: String, path: String, #[arg(long)] json: Option<String>, #[arg(long)] query: Vec<String>, #[arg(long)] step_up: Option<String> },
    /// Discover public API route templates and methods
    ApiRoutes,
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
    /// base skips your personal overrides, which is what a deployment wants
    Export { #[arg(long, default_value = "")] env: String, #[arg(long, default_value = "dotenv")] format: String, #[arg(long)] base: bool },
    Import { #[arg(long, default_value = "")] env: String, file: String },
    Run { #[arg(long, default_value = "")] env: String, #[arg(last = true)] command: Vec<String> },
    /// SSH certificates: sign a public key, or mint one and run ssh with it
    Ssh { #[command(subcommand)] cmd: SshCmd },
    E2eCreate { #[arg(long, default_value = "")] app: String, #[arg(long)] name: String },
    E2ePut { #[arg(long, default_value = "")] env: String, #[arg(long)] key: String, #[arg(long)] value: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    E2eGet { #[arg(long, default_value = "")] env: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    E2eGrant { #[arg(long, default_value = "")] env: String, #[arg(long)] email: String, #[arg(long, env = "OPENWARP_PRIVKEY")] privkey: String },
    /// Print shell completions: openwarp completion bash|zsh|fish
    Completion { shell: String },
}

#[derive(Subcommand)] enum SshCmd {
    /// Sign your OpenSSH public key and write <key>-cert.pub
    Cert {
        #[arg(long, env = "OPENWARP_SSH_CA")] ca: String,
        #[arg(long)] principal: String,
        #[arg(long)] key: Option<String>,
        #[arg(long, default_value = "15m")] ttl: String,
        #[arg(long)] out: Option<String>,
        #[arg(long)] print: bool,
        #[arg(long)] quiet: bool,
    },
    /// Mint a certificate, write it beside the key, then exec ssh
    Login {
        #[arg(long, env = "OPENWARP_SSH_CA")] ca: String,
        #[arg(long)] principal: String,
        #[arg(long)] key: Option<String>,
        #[arg(long, default_value = "15m")] ttl: String,
        #[arg(last = true)] args: Vec<String>,
    },
    /// Print the ssh_config block that mints a certificate per connection
    Config {
        #[arg(long, env = "OPENWARP_SSH_CA")] ca: String,
        #[arg(long)] principal: String,
        #[arg(long)] key: Option<String>,
    },
    /// Sign a server's host key and write <key>-cert.pub
    HostCert {
        #[arg(long, env = "OPENWARP_SSH_CA")] ca: String,
        #[arg(long)] hostname: String,
        #[arg(long)] key: String,
        #[arg(long, default_value = "30d")] ttl: String,
        #[arg(long)] print: bool,
    },
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

fn parse_ttl(raw: &str) -> i64 {
    let text = raw.trim();
    let (number, seconds) = if let Some(v) = text.strip_suffix('d') { (v, 86_400) }
        else if let Some(v) = text.strip_suffix('h') { (v, 3_600) }
        else if let Some(v) = text.strip_suffix('m') { (v, 60) }
        else if let Some(v) = text.strip_suffix('s') { (v, 1) }
        else { (text, 1) };
    match number.trim().parse::<i64>() { Ok(n) if n > 0 => n * seconds, _ => {
        eprintln!("invalid --ttl {:?}: use 90s, 15m, 2h or a number of seconds", raw); std::process::exit(2) } } }

/// The private key and the certificate path OpenSSH loads automatically
/// (`<key>-cert.pub`), derived from `--key` or from ~/.ssh/id_ed25519.
fn ssh_key_paths(explicit: &Option<String>) -> (PathBuf, PathBuf) {
    let raw = explicit.clone().unwrap_or_else(|| "~/.ssh/id_ed25519".into());
    let key = match raw.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(rest),
        None => PathBuf::from(raw),
    };
    let key = if key.extension().and_then(|e| e.to_str()) == Some("pub") { key.with_extension("") } else { key };
    let mut cert = key.clone().into_os_string();
    cert.push("-cert.pub");
    (key, PathBuf::from(cert))
}

fn read_public_key(key: &Path) -> String {
    let public = key.with_extension("pub");
    match std::fs::read_to_string(&public) {
        Ok(text) if !text.trim().is_empty() => text.trim().to_string(),
        _ => { eprintln!("no public key at {}: generate one with `ssh-keygen -t ed25519 -f {}`", public.display(), key.display()); std::process::exit(2) } } }

/// Certificates expire within hours, so one backup slot is enough to keep a
/// foreign certificate from being clobbered without accumulating files.
fn write_cert(path: &Path, certificate: &str) -> std::io::Result<()> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing.trim() != certificate.trim() {
            let backup = path.with_extension("pub.bak");
            let _ = std::fs::rename(path, &backup);
            eprintln!("previous certificate moved to {}", backup.display());
        } }
    std::fs::write(path, format!("{}\n", certificate.trim())) }

fn prompt(label: &str) -> String {
    eprint!("{}", label);
    let mut line = String::new();
    // A closed stdin is a refusal, not an empty code.
    std::io::stdin().read_line(&mut line).unwrap_or(0);
    line.trim().to_string() }

/// Complete a step-up challenge for an operation that returned 428. The server
/// emails a code and, when configured, also wants the authenticator code.
fn step_up(client: &reqwest::blocking::Client, host: &str, token: &str, required: &Value) -> String {
    let risk = required["risk"].as_str().unwrap_or("very_risky");
    let started: Value = client.post(format!("{}/api/auth/step-up/start", host)).bearer_auth(token).json(&json!({"risk": risk}))
        .send().ok().and_then(|r| r.json().ok()).unwrap_or_else(|| { eprintln!("could not start step-up verification"); std::process::exit(1) });
    let challenge = match started["challenge"].as_str() {
        Some(c) => c.to_string(),
        None => { eprintln!("step-up failed: {}", started["error"].as_str().unwrap_or("no challenge returned")); std::process::exit(1) } };
    let methods: Vec<String> = started["methods"].as_array().map(|a| a.iter().filter_map(|m| m.as_str().map(str::to_string)).collect()).unwrap_or_default();
    if methods.iter().any(|m| m == "email") { eprintln!("A verification code was emailed to you."); }
    let mut totp = String::new();
    let mut email_code = String::new();
    if methods.iter().any(|m| m == "totp") { totp = prompt("authenticator code: "); }
    if methods.iter().any(|m| m == "email") { email_code = prompt("emailed code: "); }
    let verified: Value = client.post(format!("{}/api/auth/step-up/verify", host)).bearer_auth(token)
        .json(&json!({"challenge": challenge, "totp": totp, "email_code": email_code}))
        .send().ok().and_then(|r| r.json().ok()).unwrap_or_else(|| { eprintln!("could not complete step-up verification"); std::process::exit(1) });
    match verified["token"].as_str() {
        Some(t) => t.to_string(),
        None => { eprintln!("step-up failed: {}", verified["error"].as_str().unwrap_or("no grant returned")); std::process::exit(1) } } }

/// POST a signing request, completing step-up once if the server asks for it.
fn ssh_sign_request(client: &reqwest::blocking::Client, host: &str, token: &str, path: &str, body: &Value) -> Value {
    let send = |grant: Option<&str>| {
        let mut req = client.post(format!("{}{}", host, path)).bearer_auth(token).json(body);
        if let Some(g) = grant { req = req.header("x-openwarp-step-up", g); }
        req.send() };
    let mut resp = match send(None) { Ok(r) => r, Err(e) => { eprintln!("could not reach {}: {}", host, e); std::process::exit(1) } };
    let mut status = resp.status();
    let mut parsed: Value = resp.json().unwrap_or_else(|_| json!({"error": "the server did not return JSON"}));
    if status.as_u16() == 428 {
        let grant = step_up(client, host, token, &parsed);
        resp = match send(Some(&grant)) { Ok(r) => r, Err(e) => { eprintln!("could not reach {}: {}", host, e); std::process::exit(1) } };
        status = resp.status();
        parsed = resp.json().unwrap_or_else(|_| json!({"error": "the server did not return JSON"})); }
    if !status.is_success() {
        eprintln!("signing failed ({}): {}", status.as_u16(), parsed.get("error").and_then(|e| e.as_str()).unwrap_or("no message"));
        std::process::exit(1); }
    parsed }

fn ssh_sign(client: &reqwest::blocking::Client, host: &str, token: &str, ca: &str, principal: &str, ttl: i64, public_key: &str) -> Value {
    let body = json!({"principal": principal, "ttl": ttl, "public_key": public_key});
    ssh_sign_request(client, host, token, &format!("/api/ssh/cas/{}/sign", ca), &body) }

fn ssh_summary(signed: &Value, path: Option<&Path>) {
    if let Some(p) = path { println!("certificate: {}", p.display()); }
    println!("principal:   {}", signed["principal"].as_str().unwrap_or(""));
    println!("key id:      {}", signed["key_id"].as_str().unwrap_or(""));
    println!("serial:      {}", signed["serial"]);
    let expires = signed["valid_before"].as_i64().unwrap_or(0) - now_secs();
    println!("expires in:  {}m{}s", expires / 60, expires % 60);
    println!("ca:          {}", signed["ca_public_key"].as_str().unwrap_or("")); }

fn management_path(path: &str) -> Result<(), String> {
    if !path.starts_with("/api/") || path.contains('?') || path.contains('#') { return Err("expected an /api/ path without query or fragment".into()); }
    let mut decoded = path.to_string();
    loop {
        if decoded.chars().any(char::is_control) || decoded.as_bytes().contains(&92) || decoded.contains("://")
            || decoded.split('/').any(|s| s == "." || s == "..") { return Err("unsafe API path".into()); }
        if !decoded.contains('%') { return Ok(()); }
        let bytes = decoded.as_bytes(); let mut out = Vec::new(); let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let pair = bytes.get(i+1..i+3).ok_or("malformed API path encoding")?;
                let hex = std::str::from_utf8(pair).map_err(|_| "malformed API path encoding")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "malformed API path encoding")?); i += 3;
            } else { out.push(bytes[i]); i += 1; }
        }
        decoded = String::from_utf8(out).map_err(|_| "invalid API path encoding")?;
    }
}

fn management_api(host: &str, token: &str, method: &str, path: &str, body: Option<&str>, query: &[String], step_up: Option<&str>) -> Result<(), String> {
    use std::io::Read;
    if !["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"].contains(&method) { return Err("unsupported API method".into()); }
    management_path(path)?;
    let mut url = reqwest::Url::parse(host).map_err(|_| "invalid API host")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty()
        || url.password().is_some() || url.query().is_some() || url.fragment().is_some() { return Err("invalid API host".into()); }
    url.set_path(&format!("{}{}", url.path().trim_end_matches('/'), path));
    for item in query {
        let (key,value) = item.split_once('=').ok_or("query must be key=value")?;
        url.query_pairs_mut().append_pair(key,value);
    }
    let body: Option<Value> = body.map(|input| {
        let raw = if input == "-" { let mut raw = String::new(); std::io::stdin().read_to_string(&mut raw).map_err(|_| "cannot read JSON stdin")?; raw }
            else if let Some(file) = input.strip_prefix('@') { std::fs::read_to_string(file).map_err(|_| "cannot read JSON file")? }
            else { input.to_string() };
        serde_json::from_str(&raw).map_err(|_| "invalid JSON input")
    }).transpose().map_err(str::to_string)?;
    let client = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30)).build().map_err(|_| "cannot create API client")?;
    let mut request = client.request(reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| "invalid method")?, url)
        .bearer_auth(token).header("Accept", "application/json");
    if let Some(body) = body { request = request.json(&body); }
    if let Some(grant) = step_up { request = request.header("X-OpenWarp-Step-Up", grant); }
    let response = request.send().map_err(|_| "API transport failed")?;
    let status = response.status();
    let text = response.text().map_err(|_| "cannot read API response")?;
    if !status.is_success() {
        let detail = if token.is_empty() { text } else { text.replace(token, "[redacted]") };
        let detail = if let Some(grant) = step_up { if grant.is_empty() { detail } else { detail.replace(grant, "[redacted]") } } else { detail };
        return Err(format!("HTTP {}: {}", status.as_u16(), detail));
    }
    if !text.is_empty() { println!("{}", text); }
    Ok(())
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
        Cmd::Api { method, path, json, query, step_up } => {
            if let Err(error) = management_api(&host, &token, method, path, json.as_deref(), query, step_up.as_deref()) { eprintln!("{}", error); std::process::exit(1); }
        }
        Cmd::ApiRoutes => {
            if let Err(error) = management_api(&host, &token, "GET", "/api/capabilities", None, &[], None) { eprintln!("{}", error); std::process::exit(1); }
        }
        Cmd::Login { token: t, client_id, client_secret, scope } => {
            if let Some(tok) = t { let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(tok); c["refresh_token"] = Value::Null; c["client_id"] = Value::Null; c["obtained_at"] = json!(now_secs()); save_config(&c); println!("Token saved to {}", config_path().display()); return; }
            if let (Some(cid), Some(sec)) = (client_id, client_secret) {
                let d: Value = client.post(format!("{}/api/v1/machine/auth/universal/login", host)).json(&json!({"client_id": cid, "client_secret": sec})).send().expect("req").json().expect("json");
                let at = d["accessToken"].as_str().unwrap_or_else(|| panic!("machine login failed: {}", d));
                let mut c = cfg.clone(); c["host"] = json!(host); c["access_token"] = json!(at); c["refresh_token"] = Value::Null; c["client_id"] = Value::Null; c["obtained_at"] = json!(now_secs()); save_config(&c); println!("Machine login OK (token expires in {}s)", d["expiresIn"]); return; }
            // Browser OAuth 2.1 with PKCE, loopback redirect on an ephemeral port
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port for the OAuth redirect");
            let port = listener.local_addr().expect("loopback address").port();
            let redirect = format!("http://127.0.0.1:{}/callback", port);
            let metadata: Value = client.get(format!("{}/.well-known/oauth-authorization-server", host)).send().expect("OAuth metadata").error_for_status().expect("OAuth metadata status").json().expect("OAuth metadata JSON");
            let resource = metadata["issuer"].as_str().expect("OAuth issuer").to_string();
            let reg: Value = client.post(format!("{}/oauth/register", host)).json(&json!({"client_name":"openwarp-cli","redirect_uris":[redirect],"token_endpoint_auth_method":"none","scope":scope})).send().expect("req").json().expect("json");
            let cid = reg["client_id"].as_str().expect("client_id").to_string();
            let verifier = openwarp_crypto::random_token("verifier");
            let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
            let state = openwarp_crypto::random_token("state");
            let mut url = reqwest::Url::parse(&format!("{}/oauth/authorize", host)).expect("OAuth authorization URL");
            url.query_pairs_mut().append_pair("response_type", "code").append_pair("client_id", &cid).append_pair("redirect_uri", &redirect)
                .append_pair("scope", scope.as_str()).append_pair("state", &state).append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256").append_pair("resource", &resource);
            let url = url.to_string();
            println!("Open this URL to sign in and approve:\n{}", url);
            let _ = Command::new(if cfg!(target_os = "macos") { "open" } else { "xdg-open" }).arg(url.as_str()).status();
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
        Cmd::Export { env, format, base } => { let env = pick(env, &local, "env_id", "--env"); let d = get(&format!("{}/api/envs/{}/export{}", host, env, if *base { "?base=1" } else { "" }));
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
        Cmd::Ssh { cmd } => match cmd {
            SshCmd::Cert { ca, principal, key, ttl, out, print, quiet } => {
                let (key_path, default_cert) = ssh_key_paths(key);
                let public = read_public_key(&key_path);
                let signed = ssh_sign(&client, &host, &token, ca, principal, parse_ttl(ttl), &public);
                let certificate = signed["certificate"].as_str().unwrap_or_else(|| { eprintln!("the server returned no certificate: {}", signed); std::process::exit(1) }).to_string();
                if *print {
                    println!("{}", certificate);
                    if !*quiet { ssh_summary(&signed, None); }
                } else {
                    let path = out.clone().map(PathBuf::from).unwrap_or(default_cert);
                    if let Err(e) = write_cert(&path, &certificate) { eprintln!("could not write {}: {}", path.display(), e); std::process::exit(1); }
                    if !*quiet { ssh_summary(&signed, Some(&path)); }
                } }
            SshCmd::Login { ca, principal, key, ttl, args } => {
                if args.is_empty() { eprintln!("usage: openwarp ssh login --ca <ID> --principal <name> -- <user@host> [ssh args]"); std::process::exit(2); }
                let (key_path, cert_path) = ssh_key_paths(key);
                let public = read_public_key(&key_path);
                let signed = ssh_sign(&client, &host, &token, ca, principal, parse_ttl(ttl), &public);
                let certificate = signed["certificate"].as_str().unwrap_or_else(|| { eprintln!("the server returned no certificate: {}", signed); std::process::exit(1) }).to_string();
                if let Err(e) = write_cert(&cert_path, &certificate) { eprintln!("could not write {}: {}", cert_path.display(), e); std::process::exit(1); }
                ssh_summary(&signed, Some(&cert_path));
                // The certificate is beside the key, so ssh picks it up from
                // -i; IdentitiesOnly keeps an agent from offering something else.
                let status = Command::new("ssh").arg("-i").arg(&key_path).args(["-o", "IdentitiesOnly=yes"]).args(args).status();
                match status { Ok(s) => std::process::exit(s.code().unwrap_or(1)), Err(e) => { eprintln!("could not run ssh: {}", e); std::process::exit(1) } } }
            SshCmd::Config { ca, principal, key } => {
                let (key_path, cert_path) = ssh_key_paths(key);
                println!("# ~/.ssh/config: mint a fresh certificate before each connection to matching hosts.\n\
                         # Replace the host pattern; Match exec requires OpenSSH 7.6 or newer.\n\
                         Match host *.internal exec \"openwarp ssh cert --ca {ca} --principal {principal} --quiet\"\n\
                         \x20 IdentityFile {key}\n\
                         \x20 CertificateFile {cert}",
                    ca = ca, principal = principal, key = key_path.display(), cert = cert_path.display()); }
            SshCmd::HostCert { ca, hostname, key, ttl, print } => {
                let (key_path, cert_path) = ssh_key_paths(&Some(key.clone()));
                let public = read_public_key(&key_path);
                let body = json!({"hostname": hostname, "ttl": parse_ttl(ttl), "public_key": public});
                let signed = ssh_sign_request(&client, &host, &token, &format!("/api/ssh/cas/{}/sign-host", ca), &body);
                let certificate = signed["certificate"].as_str().unwrap_or_else(|| { eprintln!("the server returned no certificate: {}", signed); std::process::exit(1) }).to_string();
                if *print {
                    println!("{}", certificate);
                } else {
                    if let Err(e) = write_cert(&cert_path, &certificate) { eprintln!("could not write {}: {}", cert_path.display(), e); std::process::exit(1); }
                    println!("certificate: {}", cert_path.display()); }
                println!("hostname:    {}", signed["hostname"].as_str().unwrap_or(""));
                println!("key id:      {}", signed["key_id"].as_str().unwrap_or(""));
                println!("expires in:  {}d", (signed["valid_before"].as_i64().unwrap_or(0) - now_secs()) / 86_400); } },
        Cmd::E2eCreate { app, name } => { let app = pick(app, &local, "app_id", "--app");
            let me = get(&format!("{}/api/me", host));
            let env_key = openwarp_crypto::random_key();
            let wrapped = openwarp_crypto::encrypt_to(me["pubkey"].as_str().expect("public key"), &env_key).expect("wrap env key");
            let d: Value = client.post(format!("{}/api/apps/{}/envs/e2e", host, app)).bearer_auth(&token).json(&json!({"name": name, "wrapped_key": wrapped})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2ePut { env, key, value, privkey } => { let env = pick(env, &local, "env_id", "--env"); let (ek, _) = e2e_env_key(&client, &host, &token, &env, privkey);
            let kname = key.to_uppercase(); let khash = openwarp_crypto::hash_token(&format!("/:{}", kname));
            let payload = json!({"secrets": [{"key_enc": openwarp_crypto::encrypt_symmetric(&ek, kname.as_bytes()), "value_enc": openwarp_crypto::encrypt_symmetric(&ek, value.as_bytes()), "key_hash": khash, "path": "/"}]});
            let d: Value = client.put(format!("{}/api/envs/{}/e2e/secrets", host, env)).bearer_auth(&token).json(&payload).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::E2eGet { env, privkey } => { let env = pick(env, &local, "env_id", "--env"); let (ek, _) = e2e_env_key(&client, &host, &token, &env, privkey);
            let d = get(&format!("{}/api/envs/{}/e2e/secrets", host, env));
            for s in d["secrets"].as_array().cloned().unwrap_or_default() { let k = openwarp_crypto::decrypt_symmetric(&ek, s["key_enc"].as_str().unwrap_or("")).unwrap(); let v = openwarp_crypto::decrypt_symmetric(&ek, s["value_enc"].as_str().unwrap_or("")).unwrap(); println!("{}={}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v)); } }
        Cmd::E2eGrant { env, email, privkey } => { let env = pick(env, &local, "env_id", "--env"); let (ek, _) = e2e_env_key(&client, &host, &token, &env, privkey);
            let u = get(&format!("{}/api/users/lookup?email={}", host, email));
            let wrapped = openwarp_crypto::encrypt_to(u["pubkey"].as_str().expect("grantee pubkey"), &ek).expect("wrap");
            let d: Value = client.post(format!("{}/api/envs/{}/e2e/grant", host, env)).bearer_auth(&token).json(&json!({"email": email, "wrapped_key": wrapped})).send().expect("req").json().expect("json"); println!("{}", d); }
        Cmd::Completion { shell } => { use clap::CommandFactory; let mut cmd = Cli::command(); let sh = match shell.as_str() { "zsh" => clap_complete::Shell::Zsh, "fish" => clap_complete::Shell::Fish, "powershell" => clap_complete::Shell::PowerShell, _ => clap_complete::Shell::Bash }; clap_complete::generate(sh, &mut cmd, "openwarp", &mut std::io::stdout()); }
    }
}
