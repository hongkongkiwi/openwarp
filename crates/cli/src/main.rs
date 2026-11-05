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
    }
}
