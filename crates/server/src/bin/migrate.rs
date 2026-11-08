//! Operator CLI for the schema migration engine.
//!
//! The server migrates on boot. This binary exists for the cases boot cannot
//! cover: inspecting a database before an upgrade, verifying checksums in CI,
//! applying a subset, and reconciling a migration that stopped part-way.

use openwarp_server::db::Db;
use openwarp_server::migrate::{self, Repair, State, MIGRATIONS};

const USAGE: &str = "\
usage: openwarp-migrate [--database-url URL] <command> [options]

commands:
  status                 show every version and the ledger state
  plan                   list pending versions
  verify                 fail when checksums, history or completion are wrong
  apply [--to N]         apply pending versions (the server also does this on boot)
  repair --version N (--set-applied | --remove | --accept-checksum)
  recover-lock --expected-owner OWNER --quiesced

The database URL defaults to DATABASE_URL. A missing scheme is a SQLite path.
Exit codes: 0 success or clean, 1 problems found, 2 invocation or connection error.";

struct Args {
    url: String,
    command: String,
    to: Option<i64>,
    version: Option<i64>,
    repair: Option<&'static str>,
    dry_run: bool,
    expected_owner: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = match parse() {
        Ok(Some(args)) => args,
        Ok(None) => { println!("{}", USAGE); return; }
        Err(error) => { eprintln!("openwarp-migrate: {}\n\n{}", error, USAGE); std::process::exit(2); }
    };
    match run(args).await {
        Ok(code) => std::process::exit(code),
        Err(error) => { eprintln!("openwarp-migrate: {}", error); std::process::exit(2); }
    }
}

fn parse() -> Result<Option<Args>, String> {
    let mut url = std::env::var("DATABASE_URL").unwrap_or_default();
    let mut command = String::new();
    let mut to = None;
    let mut version = None;
    let mut repair = None;
    let mut dry_run = false;
    let mut expected_owner = None;
    let mut quiesced = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(None),
            "--database-url" => url = arguments.next().ok_or("--database-url needs a value")?,
            "--to" => to = Some(arguments.next().ok_or("--to needs a version")?.parse::<i64>().map_err(|_| "--to needs an integer")?),
            "--version" => version = Some(arguments.next().ok_or("--version needs a version")?.parse::<i64>().map_err(|_| "--version needs an integer")?),
            "--set-applied" => repair = Some("set-applied"),
            "--remove" => repair = Some("remove"),
            "--accept-checksum" => repair = Some("accept-checksum"),
            "--dry-run" => dry_run = true,
            "--expected-owner" => expected_owner = Some(arguments.next().ok_or("--expected-owner needs a value")?),
            "--quiesced" => quiesced = true,
            other if other.starts_with('-') => return Err(format!("unknown option {}", other)),
            other => {
                if !command.is_empty() { return Err(format!("unexpected argument {}", other)); }
                command = other.to_string();
            }
        }
    }
    if command.is_empty() { return Ok(None); }
    if !matches!(command.as_str(), "status" | "plan" | "verify" | "apply" | "repair" | "recover-lock") {
        return Err(format!("unknown command {}", command));
    }
    if url.trim().is_empty() { return Err("set DATABASE_URL or pass --database-url".to_string()); }
    // Only apply has a read-only preview. Accepting the flag elsewhere and
    // ignoring it made `repair --remove --dry-run` look safe while it deleted.
    if dry_run && command != "apply" {
        return Err(format!("--dry-run is only supported by apply, not {}", command));
    }
    if command == "repair" {
        if version.is_none() { return Err("repair needs --version N".to_string()); }
        if repair.is_none() { return Err("repair needs --set-applied, --remove or --accept-checksum".to_string()); }
    }
    if command == "recover-lock" && (!quiesced || expected_owner.as_deref().is_none_or(str::is_empty)) {
        return Err("recover-lock requires --expected-owner OWNER and --quiesced after stopping all runners".to_string());
    }
    if command != "recover-lock" && (expected_owner.is_some() || quiesced) { return Err("recovery options require recover-lock".to_string()); }
    Ok(Some(Args { url, command, to, version, repair, dry_run, expected_owner }))
}

async fn run(args: Args) -> Result<i32, String> {
    // Inspection never creates a database or writes a ledger. A dry-run apply
    // is a preview too, so it opens read-only; a real apply may create one and
    // repair requires one to exist already.
    let db = if args.command == "apply" && args.dry_run {
        Db::connect_read_only(&args.url).await?
    } else {
        match args.command.as_str() {
            "status" | "plan" | "verify" => Db::connect_read_only(&args.url).await?,
            "repair" | "recover-lock" => Db::connect_existing(&args.url).await?,
            _ => Db::connect(&args.url).await?,
        }
    };
    match args.command.as_str() {
        "status" => {
            let status = migrate::status(&db, MIGRATIONS).await?;
            // The URL can carry credentials; operators know which database
            // they opened, so it is not repeated in the output.
            println!("current: {}  latest: {}", status.current, status.latest);
            print_ledger(&status);
            print_problems(&status.problems);
            Ok(if status.has_problems() { 1 } else { 0 })
        }
        "plan" => {
            let status = migrate::status(&db, MIGRATIONS).await?;
            let pending = status.pending();
            if pending.is_empty() {
                println!("no pending migrations (current {})", status.current);
            } else {
                for entry in pending { println!("{:04} {}", entry.version, entry.name); }
            }
            print_problems(&status.problems);
            Ok(if status.has_problems() { 1 } else { 0 })
        }
        "verify" => {
            let status = migrate::status(&db, MIGRATIONS).await?;
            if !status.ledger_present { println!("no ledger yet (fresh database)"); }
            if status.problems.is_empty() {
                println!("ok: current {} latest {} checksums and history agree", status.current, status.latest);
                Ok(0)
            } else {
                print_problems(&status.problems);
                Ok(1)
            }
        }
        "apply" => {
            if args.dry_run {
                let status = migrate::status(&db, MIGRATIONS).await?;
                for entry in status.pending() { println!("would apply {:04} {}", entry.version, entry.name); }
                print_problems(&status.problems);
                return Ok(if status.has_problems() { 1 } else { 0 });
            }
            let report = migrate::apply(&db, MIGRATIONS, migrate::Options { to: args.to }).await?;
            if report.squashed { println!("applied the consolidated baseline (versions 2-{} recorded as squashed)", migrate::SQUASHED_THROUGH); }
            if report.applied.is_empty() {
                println!("already current (version {})", db.version().await?);
            } else {
                for version in &report.applied { println!("applied {:04}", version); }
                println!("now at version {}", db.version().await?);
            }
            Ok(0)
        }
        "recover-lock" => {
            migrate::recover_lock(&db, args.expected_owner.as_deref().expect("validated")).await?;
            println!("matching migration lock removed; inspect incomplete history before applying");
            Ok(0)
        }
        "repair" => {
            let version = args.version.expect("validated");
            let action = match args.repair {
                Some("set-applied") => Repair::SetApplied(version),
                Some("remove") => Repair::Remove(version),
                Some("accept-checksum") => Repair::AcceptChecksum(version),
                _ => return Err("unknown repair action".to_string()),
            };
            println!("{}", migrate::repair(&db, MIGRATIONS, action).await?);
            Ok(0)
        }
        other => Err(format!("unknown command {}", other)),
    }
}

fn print_ledger(status: &migrate::Status) {
    for entry in &status.entries {
        println!("  {:04}  {:<8} {}", entry.version, label(entry.state), entry.name);
    }
}

fn label(state: State) -> &'static str {
    match state {
        State::Applied => "applied",
        State::Legacy => "legacy",
        State::Squashed => "squashed",
        State::Pending => "pending",
        State::Failed => "failed",
    }
}

fn print_problems(problems: &[migrate::Problem]) {
    if problems.is_empty() { return; }
    eprintln!("problems:");
    for problem in problems { eprintln!("  {}", problem.describe()); }
}
