//! Versioned schema migrations shared by every storage backend.
//!
//! A migration is an immutable SQL file identified by a monotonically
//! increasing version. The ledger (`schema_migrations`) records its checksum and
//! completion state. Startup refuses to continue when an applied file changed,
//! when the database is newer than this binary, when history has a gap, or when
//! a previous attempt did not finish.
//!
//! Databases created before the ledger tracked checksums replay the frozen
//! history from where they stopped. Fresh databases apply the consolidated
//! baseline and record versions through [`SQUASHED_THROUGH`] as squashed, so
//! they do not replay history that the baseline already contains.
//!
//! Backends implement [`Target`]; [`Db`] covers SQLite, PostgreSQL, MariaDB and
//! the Durable Object SQLite handle, and [`worker::D1Database`] covers D1. The
//! public runner dispatches ownership through the target before executing SQL.

use crate::db::{n, s, Db, Row};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use std::future::Future;

/// A frozen migration. `tolerant` allows duplicate columns and guarded indexes
/// when reconciling schemas that already contain those objects.
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
    pub tolerant: bool,
}

/// The consolidated baseline replaces every version up to and including this
/// one on a database with no ledger.
pub const SQUASHED_THROUGH: i64 = 17;

pub const MIGRATIONS: &[Migration] = &[
    Migration { version: 1, name: "baseline", sql: include_str!("../migrations/0001_baseline.sql"), tolerant: false },
    Migration { version: 2, name: "token_scopes", sql: include_str!("../migrations/0002_token_scopes.sql"), tolerant: true },
    Migration { version: 3, name: "team_env_grants", sql: include_str!("../migrations/0003_team_env_grants.sql"), tolerant: true },
    Migration { version: 4, name: "instance_leases", sql: include_str!("../migrations/0004_instance_leases.sql"), tolerant: true },
    Migration { version: 5, name: "saml", sql: include_str!("../migrations/0005_saml.sql"), tolerant: true },
    Migration { version: 6, name: "rotation_hooks", sql: include_str!("../migrations/0006_rotation_hooks.sql"), tolerant: true },
    Migration { version: 7, name: "social_pkce", sql: include_str!("../migrations/0007_social_pkce.sql"), tolerant: true },
    Migration { version: 8, name: "live_events", sql: include_str!("../migrations/0008_live_events.sql"), tolerant: true },
    Migration { version: 9, name: "account_linking", sql: include_str!("../migrations/0009_account_linking.sql"), tolerant: true },
    Migration { version: 10, name: "ldap", sql: include_str!("../migrations/0010_ldap.sql"), tolerant: true },
    Migration { version: 11, name: "rotation_config", sql: include_str!("../migrations/0011_rotation_config.sql"), tolerant: true },
    Migration { version: 12, name: "reuse_detection", sql: include_str!("../migrations/0012_reuse_detection.sql"), tolerant: true },
    Migration { version: 13, name: "secret_version_paths", sql: include_str!("../migrations/0013_secret_version_paths.sql"), tolerant: true },
    Migration { version: 14, name: "ssh_ca", sql: include_str!("../migrations/0014_ssh_ca.sql"), tolerant: true },
    Migration { version: 15, name: "ssh_hosts_and_step_up", sql: include_str!("../migrations/0015_ssh_hosts_and_step_up.sql"), tolerant: true },
    Migration { version: 16, name: "delegated_envs_and_auth_v2", sql: include_str!("../migrations/0016_delegated_envs_and_auth_v2.sql"), tolerant: true },
    Migration { version: 17, name: "legacy_columns", sql: include_str!("../migrations/0017_legacy_columns.sql"), tolerant: true },
    Migration { version: 18, name: "env_restricted_backfill", sql: include_str!("../migrations/0018_env_restricted_backfill.sql"), tolerant: false },
    Migration { version: 19, name: "main17_reconciliation", sql: include_str!("../migrations/0019_main17_reconciliation.sql"), tolerant: true },
    Migration { version: 20, name: "main18_reconciliation", sql: include_str!("../migrations/0020_main18_reconciliation.sql"), tolerant: true },
    Migration { version: 21, name: "change_requests", sql: include_str!("../migrations/0021_change_requests.sql"), tolerant: true },
    Migration { version: 22, name: "main21_reconciliation", sql: include_str!("../migrations/0022_main21_reconciliation.sql"), tolerant: true },
    Migration { version: 23, name: "main22_reconciliation", sql: include_str!("../migrations/0023_main22_reconciliation.sql"), tolerant: true },
    Migration { version: 24, name: "main23_reconciliation", sql: include_str!("../migrations/0024_main23_reconciliation.sql"), tolerant: true },
    Migration { version: 25, name: "main24_reconciliation", sql: include_str!("../migrations/0025_main24_reconciliation.sql"), tolerant: true },
    Migration { version: 26, name: "main25_reconciliation", sql: include_str!("../migrations/0026_main25_reconciliation.sql"), tolerant: true },
    Migration { version: 27, name: "main27_reconciliation", sql: include_str!("../migrations/0027_main27_reconciliation.sql"), tolerant: true },
    Migration { version: 28, name: "lineage_convergence", sql: include_str!("../migrations/0028_lineage_convergence.sql"), tolerant: true },
    // Tolerant because a database that already ran PR7's former inline
    // migration 18 carries these columns and meta rows.
    Migration { version: 29, name: "workspace_policy", sql: include_str!("../migrations/0029_workspace_policy.sql"), tolerant: true },
    Migration { version: 30, name: "ai_assistant", sql: include_str!("../migrations/0030_ai_assistant.sql"), tolerant: false },
    Migration { version: 31, name: "feature_grants", sql: include_str!("../migrations/0031_feature_grants.sql"), tolerant: true },
    Migration { version: 32, name: "session_ids", sql: include_str!("../migrations/0032_session_ids.sql"), tolerant: true },
    Migration { version: 33, name: "webhooks", sql: include_str!("../migrations/0033_webhooks.sql"), tolerant: true },
    Migration { version: 34, name: "workspace_member_locks", sql: include_str!("../migrations/0034_workspace_member_locks.sql"), tolerant: true },
    Migration { version: 35, name: "private_workers", sql: include_str!("../migrations/0035_private_workers.sql"), tolerant: true },
    Migration { version: 36, name: "identity_linking", sql: include_str!("../migrations/0036_identity_linking.sql"), tolerant: true },
];

/// SQL profile used when splitting migration statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlDialect { Legacy, Sqlite, Postgres, Mysql }

/// A storage backend the runner can drive. Statements are raw: migrations are
/// not parameterised, and a literal `?` in SQL text must never be rewritten.
#[allow(async_fn_in_trait)] // awaited inline; these futures are never spawned
pub trait Target {
    async fn apply(&self, migrations: &[Migration], options: Options) -> Result<Report, String> where Self: Sized { apply_generic(self, migrations, options).await }
    async fn repair(&self, migrations: &[Migration], action: Repair) -> Result<String, String> where Self: Sized { repair_generic(self, migrations, action).await }
    async fn exec(&self, sql: &str) -> Result<(), String>;
    async fn query(&self, sql: &str) -> Result<Vec<Row>, String>;
    /// Apply statements as one unit where the backend can. MySQL commits DDL
    /// implicitly, so its callers must treat a failure as partial.
    async fn script(&self, statements: &[String]) -> Result<(), String>;
    /// True when a failed `script` left no changes behind.
    fn atomic_ddl(&self) -> bool;
    /// Defaults to the legacy splitter for existing target implementations.
    fn sql_dialect(&self) -> SqlDialect { SqlDialect::Legacy }
    /// True when application objects exist outside the migration ledger. A
    /// fresh database has none. A database that predates the ledger does, and
    /// recording the consolidated baseline as squashed there would certify
    /// schema the runner never applied. Every backend answers from its own
    /// catalogue; there is deliberately no permissive default.
    async fn has_application_schema(&self) -> Result<bool, String>;
}

impl Target for Db {
    async fn apply(&self, migrations: &[Migration], options: Options) -> Result<Report, String> { self.migration_apply(migrations, options).await }
    async fn repair(&self, migrations: &[Migration], action: Repair) -> Result<String, String> { self.migration_repair(migrations, action).await }
    async fn exec(&self, sql: &str) -> Result<(), String> { Db::exec_raw(self, sql).await }
    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> { Db::query_raw(self, sql).await }
    async fn script(&self, statements: &[String]) -> Result<(), String> { Db::exec_script(self, statements).await }
    fn atomic_ddl(&self) -> bool { Db::script_is_atomic(self) }
    fn sql_dialect(&self) -> SqlDialect {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Db::Sqlite(_) => SqlDialect::Sqlite,
            #[cfg(not(target_arch = "wasm32"))]
            Db::Postgres(_) => SqlDialect::Postgres,
            #[cfg(not(target_arch = "wasm32"))]
            Db::Mysql(_) => SqlDialect::Mysql,
            #[cfg(target_arch = "wasm32")]
            Db::DoSqlite(_, _) => SqlDialect::Sqlite,
        }
    }
    async fn has_application_schema(&self) -> Result<bool, String> { Db::has_application_schema(self).await }
}

/// Cloudflare D1 has no connection of its own; migrations run in the Worker
/// that owns the binding. `batch` is the atomic unit, so a strict migration is
/// one batch and a failed batch leaves no changes behind.
#[cfg(target_arch = "wasm32")]
impl Target for worker::D1Database {
    // D1's `exec` splits its input on newlines, which mangles a multi-line
    // statement. `prepare().run()` executes exactly one statement as written,
    // driven through js_sys so every JS rejection surfaces as Err: the worker
    // crate's own binding is not `catch`-marked, and a throw would abort the
    // module before exec_tolerant could apply convergence tolerance to
    // lineage migrations that re-add columns the squashed baseline carries.
    async fn exec(&self, sql: &str) -> Result<(), String> {
        use worker::wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let raw: &JsValue = self.as_ref();
        let prepare = js_sys::Reflect::get(raw, &JsValue::from_str("prepare")).map_err(|e| worker::Error::from(e).to_string())?
            .dyn_into::<js_sys::Function>().map_err(|_| "D1 prepare is unavailable".to_string())?;
        let request = prepare.call1(raw, &JsValue::from_str(sql)).map_err(|e| worker::Error::from(e).to_string())?;
        let all = js_sys::Reflect::get(&request, &JsValue::from_str("all")).map_err(|e| worker::Error::from(e).to_string())?
            .dyn_into::<js_sys::Function>().map_err(|_| "D1 all is unavailable".to_string())?;
        let promise = all.call0(&request).map_err(|e| worker::Error::from(e).to_string())?
            .dyn_into::<js_sys::Promise>().map_err(|_| "D1 all did not return a promise".to_string())?;
        // A rejected promise becomes Err here, so lineage migrations whose
        // columns already exist are classified by exec_tolerant as converged.
        JsFuture::from(promise).await.map(|_| ()).map_err(|e| { let e = js_sys::Error::try_from(e).ok(); e.and_then(|e| e.message().try_into().ok()).unwrap_or_else(|| "D1 statement failed".into()) })
    }
    async fn query(&self, sql: &str) -> Result<Vec<Row>, String> {
        let result = self.prepare(sql).all().await.map_err(|e| e.to_string())?;
        let rows: Vec<HashMap<String, serde_json::Value>> = result.results().map_err(|e| e.to_string())?;
        Ok(rows.into_iter().map(|row| row.into_iter().map(|(k, v)| (k, d1_normal(v))).collect()).collect())
    }
    async fn script(&self, statements: &[String]) -> Result<(), String> {
        let batch = statements.iter().map(|sql| self.prepare(sql.clone())).collect();
        self.batch(batch).await.map(|_| ()).map_err(|e| e.to_string())
    }
    fn atomic_ddl(&self) -> bool { true }
    fn sql_dialect(&self) -> SqlDialect { SqlDialect::Sqlite }
    async fn has_application_schema(&self) -> Result<bool, String> {
        // D1 is SQLite underneath: its own bookkeeping tables are `_cf_*` and
        // `d1_*`, alongside SQLite's `sqlite_*`.
        let rows = self.query(
            "SELECT name FROM sqlite_master WHERE type='table' \
             AND substr(name,1,7)<>'sqlite_' AND substr(name,1,4)<>'_cf_' AND substr(name,1,3)<>'d1_' \
             AND name NOT IN ('schema_migrations','schema_migration_lock') LIMIT 1",
        ).await?;
        Ok(!rows.is_empty())
    }
}

/// serde-wasm-bindgen represents every JavaScript number as f64, so an integer
/// column would otherwise read back as `1.0` and `as_i64()` would return None.
#[cfg(target_arch = "wasm32")]
fn d1_normal(value: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::Number(number) = &value {
        if number.as_i64().is_none() {
            if let Some(float) = number.as_f64() {
                if float.fract() == 0.0 && float.abs() < 9.0e15 {
                    return serde_json::json!(float as i64);
                }
            }
        }
    }
    value
}

#[derive(Clone, Debug)]
pub struct LedgerRow {
    pub version: i64,
    pub name: String,
    pub checksum: String,
    pub success: bool,
    pub execution_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Problem {
    /// The file changed after it was applied.
    Checksum { version: i64 },
    /// A previous run stopped before recording completion.
    Incomplete { version: i64 },
    /// The database was migrated by a newer binary.
    Newer { version: i64, latest: i64 },
    /// A ledger row this binary does not know about.
    Unknown { version: i64 },
    /// A later version is applied while an earlier one is not.
    Gap { version: i64 },
    /// Application tables exist without recorded migration history.
    MissingHistory,
    /// The ledger has only some of the migration metadata columns.
    PartialMetadata,
}

impl Problem {
    pub fn describe(&self) -> String {
        match self {
            Problem::Checksum { version } => format!("migration {} was edited after it was applied (checksum mismatch)", version),
            Problem::Incomplete { version } => format!("migration {} did not complete; repair it before starting", version),
            Problem::Newer { version, latest } => format!("database is newer than this binary (version {}, this binary knows {}); refusing to run an older schema", version, latest),
            Problem::Unknown { version } => format!("database recorded migration {} which this binary does not contain", version),
            Problem::Gap { version } => format!("migration {} is missing while a later version is applied", version),
            Problem::MissingHistory => "database contains application tables but no migration history".to_string(),
            Problem::PartialMetadata => "migration ledger has incomplete metadata columns; inspect its history before repair".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Applied,
    /// Applied before checksums were tracked.
    Legacy,
    /// Covered by the consolidated baseline.
    Squashed,
    Pending,
    Failed,
}

pub struct Entry {
    pub version: i64,
    pub name: &'static str,
    pub state: State,
}

pub struct Status {
    pub current: i64,
    pub latest: i64,
    pub entries: Vec<Entry>,
    pub problems: Vec<Problem>,
    /// False when the ledger table (or its metadata columns) is not readable.
    pub ledger_present: bool,
    /// A proven baseline whose remaining squash markers will be recorded on apply.
    pub interrupted_squash: bool,
}

impl Status {
    pub fn pending(&self) -> Vec<&Entry> { self.entries.iter().filter(|e| e.state == State::Pending).collect() }
    pub fn has_problems(&self) -> bool { !self.problems.is_empty() }
}

#[derive(Debug, Default)]
pub struct Report {
    pub applied: Vec<i64>,
    pub squashed: bool,
}

#[derive(Default, Clone, Copy)]
pub struct Options {
    /// Stop after this version. A fresh database still squashes through
    /// [`SQUASHED_THROUGH`], because the baseline already contains those files.
    pub to: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
pub enum Repair {
    /// Mark an interrupted migration complete after checking the schema.
    SetApplied(i64),
    /// Delete the ledger row so the next apply runs the migration again.
    Remove(i64),
    /// Accept the current file's checksum after reviewing the difference.
    AcceptChecksum(i64),
}

pub async fn run<T: Target>(target: &T) -> Result<(), String> {
    apply(target, MIGRATIONS, Options::default()).await.map(|_| ())
}

/// Apply pending migrations. Verifies the whole ledger first and holds the
/// cross-process lock for the duration, including the ledger write.
pub async fn apply<T: Target>(target: &T, migrations: &[Migration], options: Options) -> Result<Report, String> {
    target.apply(migrations, options).await
}

async fn apply_generic<T: Target>(target: &T, migrations: &[Migration], options: Options) -> Result<Report, String> {
    validate(migrations)?;
    let mut report = Report::default();
    ensure_lock_table(target).await?;
    let lock = Lock::acquire(target).await?;
    let result = async {
        ensure_ledger(target).await?;
        apply_locked(target, migrations, options, &mut report).await
    }.await;
    // A transport error can leave submitted SQL running. Only verified success
    // proves that a generic target's owner may release its persistent claim.
    if result.is_ok() { lock.release().await; }
    result?;
    Ok(report)
}

pub(crate) async fn apply_owned<T: Target>(target: &T, migrations: &[Migration], options: Options) -> Result<Report, String> {
    validate(migrations)?;
    ensure_native_protocol(target).await?;
    ensure_ledger(target).await?;
    let mut report = Report::default();
    apply_locked(target, migrations, options, &mut report).await?;
    Ok(report)
}

const NATIVE_PROTOCOL: &str = "native-session-v1";

// The shared primary key arbitrates native protocol initialization against
// generic claims. This marker is permanent, not a recoverable run owner.
async fn ensure_native_protocol<T: Target>(target: &T) -> Result<(), String> {
    ensure_lock_table(target).await?;
    let inserted = target.exec(&format!(
        "INSERT INTO schema_migration_lock(id,owner,acquired_at) VALUES(1,'{}',0)", NATIVE_PROTOCOL,
    )).await;
    if inserted.is_ok() { return Ok(()); }
    let row = target.query("SELECT owner FROM schema_migration_lock WHERE id=1").await?.into_iter().next();
    if row.as_ref().is_some_and(|row| s(row, "owner") == NATIVE_PROTOCOL) { return Ok(()); }
    reject_persistent_owner(target).await?;
    Err("could not initialize native migration ownership protocol; retry".to_string())
}

async fn reject_persistent_owner<T: Target>(target: &T) -> Result<(), String> {
    if let Some(row) = target.query("SELECT owner FROM schema_migration_lock WHERE id=1").await?.first() {
        let owner = s(row, "owner");
        if owner == NATIVE_PROTOCOL {
            return Err("database uses native-session-v1 migration ownership; this permanent protocol marker is not an active lock. Use Db apply/repair or an explicitly forwarding target".to_string());
        }
        return Err(format!("migration lock held by {:?}; confirm all previous runners are stopped before owner-qualified recovery", owner));
    }
    Ok(())
}

fn interrupted_squash(rows: &[LedgerRow], migrations: &[Migration]) -> bool {
    !rows.is_empty() && rows.len() < SQUASHED_THROUGH as usize
        && rows[0].version == 1 && rows[0].name == "baseline" && rows[0].success
        && rows[0].checksum == checksum(migrations[0].sql)
        && rows.iter().skip(1).enumerate().all(|(index, row)| {
            row.version == index as i64 + 2 && row.success && row.checksum == "squashed"
        })
}

async fn apply_locked<T: Target>(target: &T, migrations: &[Migration], options: Options, report: &mut Report) -> Result<(), String> {
    let rows = read_ledger(target).await?;
    let problems = check(&rows, migrations);
    if !problems.is_empty() {
        return Err(problems.iter().map(Problem::describe).collect::<Vec<_>>().join("; "));
    }
    // Rows written before checksums existed have no hash to verify. Versions
    // 2-16 were extracted verbatim from the code that applied them, so their
    // current files are the record; version 1 is the consolidated baseline and
    // deliberately stays unverified on an upgraded database. This runs only
    // after the ledger is known to describe this binary's schema.
    backfill_legacy(target, &rows, migrations).await?;

    let mut done: BTreeSet<i64> = rows.iter().map(|r| r.version).collect();
    if rows.is_empty() {
        // Squashing records the baseline as applied without running it. That is
        // only sound on a genuinely empty database: if application tables are
        // already present, the ledger was lost or never created, and certifying
        // versions 2..=SQUASHED_THROUGH would mark migrations the schema never
        // received. Fail closed instead of silently skipping them.
        if target.has_application_schema().await? {
            return Err("database contains application tables but no schema_migrations ledger; refusing to record the consolidated baseline as squashed. \
                        Restore the ledger, or recreate the database, before applying migrations".to_string());
        }
        apply_one(target, &migrations[0]).await?;
        done.insert(1);
        report.applied.push(1);
        for migration in migrations.iter().filter(|m| m.version > 1 && m.version <= SQUASHED_THROUGH) {
            insert_squashed(target, migration).await?;
            done.insert(migration.version);
        }
        report.squashed = true;
    } else if interrupted_squash(&rows, migrations) {
        // Only a completed modern baseline followed by squash markers proves
        // that the missing prefix was covered before an interrupted write.
        for migration in migrations.iter().filter(|m| m.version > 1 && m.version <= SQUASHED_THROUGH && !done.contains(&m.version)) {
            insert_squashed(target, migration).await?;
        }
        done.extend(2..=SQUASHED_THROUGH);
    }

    for migration in migrations {
        if done.contains(&migration.version) { continue; }
        if let Some(to) = options.to { if migration.version > to { break; } }
        apply_one(target, migration).await?;
        done.insert(migration.version);
        report.applied.push(migration.version);
    }
    Ok(())
}

async fn apply_one<T: Target>(target: &T, migration: &Migration) -> Result<(), String> {
    let checksum = checksum(migration.sql);
    let started = now_ms();
    let insert = format!(
        "INSERT INTO schema_migrations(version,applied_at,name,checksum,success,execution_ms) VALUES({},{},'{}','{}',0,0)",
        migration.version, crate::clock::now(), sql_literal(migration.name), checksum,
    );
    let statements = split_sql_with_dialect(migration.sql, target.sql_dialect());
    if !migration.tolerant && target.atomic_ddl() {
        let mut atomic = vec![insert];
        atomic.extend(statements);
        atomic.push(format!("UPDATE schema_migrations SET success=1 WHERE version={}", migration.version));
        target.script(&atomic).await.map_err(|error| format!("migration {} ({}) failed; transaction outcome must be verified before retry: {}", migration.version, migration.name, error))?;
        return verify_completion(target, migration, &checksum).await;
    }
    target.exec(&insert).await?;
    let outcome = if migration.tolerant {
        exec_tolerant(target, &statements, migration.version <= SQUASHED_THROUGH).await
    } else {
        target.script(&statements).await
    };
    let elapsed = (now_ms() - started).max(0);

    match outcome {
        Ok(()) => {
            target.exec(&format!(
                "UPDATE schema_migrations SET success=1, execution_ms={} WHERE version={}",
                elapsed, migration.version,
            )).await?;
            // Completion must identify the exact row this operation inserted.
            verify_completion(target, migration, &checksum).await
        }
        Err(error) => Err(format!(
            "migration {} ({}) failed part-way: {}. The database is marked incomplete; after checking the schema run \
             `openwarp-migrate repair --version {} --set-applied`, or `--remove` to retry from scratch",
            migration.version, migration.name, error, migration.version,
        )),
    }
}

/// Confirm the completion write landed on the row this run inserted. The
/// version, name and checksum identify that row; `success=1` is its completion
/// marker. Anything else means concurrent history (for example an operator
/// repairing after a stale-lock takeover), and reporting success would be a
/// lie about the schema this binary applied.
async fn verify_completion<T: Target>(target: &T, migration: &Migration, checksum: &str) -> Result<(), String> {
    let row = target.query(&format!(
        "SELECT version, name, checksum, success FROM schema_migrations WHERE version={}",
        migration.version,
    )).await?
        .into_iter().next()
        .ok_or_else(|| format!(
            "migration {} ({}) completed but its ledger row is gone; another runner may have removed it. Refusing to report success",
            migration.version, migration.name,
        ))?;
    let version = n(&row, "version");
    let name = s(&row, "name");
    let stored = s(&row, "checksum");
    let success = n(&row, "success") != 0;
    if version != migration.version || name != migration.name || stored != checksum || !success {
        return Err(format!(
            "migration {} ({}) completed but its ledger row was rewritten (version {}, name {:?}, checksum {}, success {}); refusing to report success",
            migration.version, migration.name, version, name, stored, success,
        ));
    }
    Ok(())
}

async fn exec_tolerant<T: Target>(target: &T, statements: &[String], legacy: bool) -> Result<(), String> {
    for statement in statements {
        if let Err(error) = target.exec(statement).await {
            if if legacy { is_duplicate(&error) } else { is_convergence_duplicate(statement, &error) } { continue; }
            return Err(error);
        }
    }
    Ok(())
}

fn is_convergence_duplicate(statement: &str, error: &str) -> bool {
    let words: Vec<_> = statement.split_whitespace().collect();
    let message = error.to_ascii_lowercase();
    // Only the column named by this ADD may already exist, not another failure
    // whose text happens to mention an existing object or a unique constraint.
    if let ["ALTER", "TABLE", table, "ADD", "COLUMN", column, ..] = words.as_slice() {
        return message.split_once("duplicate column name: ")
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|name| name.trim_end_matches(':') == *column)
            || message.contains(&format!("duplicate column name '{}'", column))
            || message.contains(&format!("column \"{}\" of relation \"{}\" already exists", column, table));
    }
    // MySQL strips IF NOT EXISTS from index DDL; other engines keep the guard.
    if let ["CREATE", "INDEX", "IF", "NOT", "EXISTS", index, ..]
        | ["CREATE", "UNIQUE", "INDEX", "IF", "NOT", "EXISTS", index, ..] = words.as_slice() {
        return message.contains(&format!("duplicate key name '{}'", index));
    }
    false
}

fn is_duplicate(error: &str) -> bool {
    let message = error.to_ascii_lowercase();
    message.contains("duplicate column")
        || message.contains("already exists")
        || message.contains("duplicate key name")
        // PostgreSQL's CREATE TABLE IF NOT EXISTS race on its catalogue index.
        || message.contains("duplicate key value violates unique constraint")
        || message.contains("tuple concurrently updated")
}

fn is_missing_relation(error: &str) -> bool {
    let message = error.to_ascii_lowercase();
    message.contains("no such table") || message.contains("unknown table")
        || ((message.contains("relation") || message.contains("table"))
            && (message.contains("does not exist") || message.contains("doesn't exist")))
}

async fn insert_squashed<T: Target>(target: &T, migration: &Migration) -> Result<(), String> {
    target.exec(&format!(
        "INSERT INTO schema_migrations(version,applied_at,name,checksum,success,execution_ms) VALUES({},{},'{}','squashed',1,0)",
        migration.version, crate::clock::now(), sql_literal(migration.name),
    )).await
}

async fn read_ledger<T: Target>(target: &T) -> Result<Vec<LedgerRow>, String> {
    let rows = target.query("SELECT version, name, checksum, success, execution_ms FROM schema_migrations ORDER BY version").await?;
    Ok(rows.iter().map(|row| LedgerRow {
        version: n(row, "version"),
        name: s(row, "name"),
        checksum: s(row, "checksum"),
        // Older ledgers gained this column with a default of 1.
        success: n(row, "success") != 0,
        execution_ms: n(row, "execution_ms"),
    }).collect())
}

async fn backfill_legacy<T: Target>(target: &T, rows: &[LedgerRow], migrations: &[Migration]) -> Result<(), String> {
    for row in rows {
        if !row.checksum.is_empty() || !(2..=16).contains(&row.version) { continue; }
        let Some(migration) = migrations.iter().find(|m| m.version == row.version) else { continue };
        target.exec(&format!(
            "UPDATE schema_migrations SET name='{}', checksum='{}' WHERE version={} AND checksum=''",
            sql_literal(migration.name), checksum(migration.sql), row.version,
        )).await?;
    }
    Ok(())
}

/// Read-only view used by status and plan. It falls back to the pre-engine
/// ledger shape, and to an empty ledger when the table does not exist yet.
pub async fn status<T: Target>(target: &T, migrations: &[Migration]) -> Result<Status, String> {
    validate(migrations)?;
    let (rows, ledger_present, partial_metadata) = match read_ledger(target).await {
        Ok(rows) => (rows, true, false),
        // A ledger from an older binary lacks the metadata columns; fall back to
        // the version-only shape before deciding the table is absent.
        Err(error) => match target.query("SELECT version, applied_at FROM schema_migrations ORDER BY version").await {
            Ok(rows) => {
                let message = error.to_ascii_lowercase();
                if !(message.contains("no such column") || message.contains("unknown column")
                    || (message.contains("column") && message.contains("does not exist"))) { return Err(error); }
                let catalog = match target.sql_dialect() {
                    SqlDialect::Sqlite => "SELECT name FROM pragma_table_info('schema_migrations')",
                    SqlDialect::Postgres => "SELECT column_name AS name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='schema_migrations'",
                    SqlDialect::Mysql => "SELECT column_name AS name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='schema_migrations'",
                    SqlDialect::Legacy => return Err(error),
                };
                let columns: BTreeSet<String> = target.query(catalog).await?.iter().map(|row| s(row, "name")).collect();
                let partial = columns != BTreeSet::from(["version".to_string(), "applied_at".to_string()]);
                let rows = if partial {
                    let select = |column: &str, default: &str| {
                        if columns.contains(column) { column.to_string() } else { format!("{} AS {}", default, column) }
                    };
                    target.query(&format!("SELECT version, {}, {}, {}, {} FROM schema_migrations ORDER BY version",
                        select("name", "''"), select("checksum", "''"), select("success", "0"), select("execution_ms", "0"))).await?
                } else { rows };
                (rows.iter().map(|row| LedgerRow {
                    version: n(row, "version"), name: s(row, "name"), checksum: s(row, "checksum"),
                    success: if partial { n(row, "success") != 0 } else { true }, execution_ms: n(row, "execution_ms"),
                }).collect(), true, partial)
            }
            Err(probe_error) if is_missing_relation(&probe_error) => (Vec::new(), false, false),
            Err(probe_error) => return Err(probe_error),
        },
    };
    let mut problems = check(&rows, migrations);
    if partial_metadata { problems.push(Problem::PartialMetadata); }
    if rows.is_empty() && target.has_application_schema().await? { problems.push(Problem::MissingHistory); }
    let interrupted_squash = !partial_metadata && interrupted_squash(&rows, migrations);
    let current = rows.iter().filter(|r| r.success).map(|r| r.version).max().unwrap_or(0);
    let entries = migrations.iter().map(|migration| Entry {
        version: migration.version,
        name: migration.name,
        state: match rows.iter().find(|row| row.version == migration.version) {
            None => State::Pending,
            Some(row) if !row.success => State::Failed,
            Some(row) if row.checksum == "squashed" => State::Squashed,
            Some(row) if row.checksum.is_empty() => State::Legacy,
            Some(_) => State::Applied,
        },
    }).collect();
    Ok(Status { current, latest: migrations.last().map(|m| m.version).unwrap_or(0), entries, problems, ledger_present, interrupted_squash })
}

pub async fn repair<T: Target>(target: &T, migrations: &[Migration], action: Repair) -> Result<String, String> {
    target.repair(migrations, action).await
}

async fn repair_generic<T: Target>(target: &T, migrations: &[Migration], action: Repair) -> Result<String, String> {
    validate(migrations)?;
    // A repair must never manufacture a ledger in a database that has none.
    if target.query("SELECT version FROM schema_migrations LIMIT 1").await.is_err() {
        return Err("no schema_migrations ledger in this database; run status or apply first".to_string());
    }
    ensure_lock_table(target).await?;
    let lock = Lock::acquire(target).await?;
    let result = async {
        ensure_ledger(target).await?;
        repair_locked(target, migrations, action).await
    }.await;
    if result.is_ok() { lock.release().await; }
    result
}

pub(crate) async fn repair_owned<T: Target>(target: &T, migrations: &[Migration], action: Repair) -> Result<String, String> {
    validate(migrations)?;
    target.query("SELECT version FROM schema_migrations LIMIT 1").await.map_err(|_| "no schema_migrations ledger in this database; run status or apply first".to_string())?;
    ensure_native_protocol(target).await?;
    ensure_ledger(target).await?;
    repair_locked(target, migrations, action).await
}

/// Only call after quiescing every migration runner, including remote requests.
pub async fn recover_lock<T: Target>(target: &T, expected_owner: &str) -> Result<(), String> {
    if expected_owner.is_empty() { return Err("expected lock owner is required".to_string()); }
    if expected_owner == NATIVE_PROTOCOL { return Err("native-session-v1 is a permanent protocol marker, not an abandoned owner; it cannot be removed by recovery".to_string()); }
    target.exec(&format!("DELETE FROM schema_migration_lock WHERE id=1 AND owner='{}'", sql_literal(expected_owner))).await?;
    reject_persistent_owner(target).await
}

async fn repair_locked<T: Target>(target: &T, migrations: &[Migration], action: Repair) -> Result<String, String> {
    let version = match action { Repair::SetApplied(v) | Repair::Remove(v) | Repair::AcceptChecksum(v) => v };
    let migration = migrations.iter().find(|m| m.version == version)
        .ok_or_else(|| format!("no migration {} in this binary", version))?;
    let row = target.query(&format!("SELECT version, checksum, success FROM schema_migrations WHERE version={}", version)).await?
        .into_iter().next()
        .ok_or_else(|| format!("migration {} has no ledger row", version))?;
    let stored = s(&row, "checksum");
    let completed = n(&row, "success") != 0;
    match action {
        Repair::SetApplied(_) => {
            // Only an interrupted run carries the incomplete marker this
            // command is allowed to complete. Marking an already-applied or
            // absent migration would be a guess about the schema.
            if completed {
                return Err(format!("migration {} is already marked applied", version));
            }
            target.exec(&format!("UPDATE schema_migrations SET success=1 WHERE version={} AND success=0", version)).await?;
            let marker = target.query(&format!("SELECT success FROM schema_migrations WHERE version={}", version)).await?
                .into_iter().next().is_some_and(|row| n(&row, "success") != 0);
            if !marker {
                return Err(format!("migration {} completion marker did not persist", version));
            }
            Ok(format!("migration {} marked applied", version))
        }
        Repair::Remove(_) => {
            // Only an interrupted run may be removed and retried. Deleting a
            // completed row replays DDL that already succeeded.
            if completed {
                return Err(format!("migration {} completed; refusing to remove it and re-run history", version));
            }
            let latest = target.query("SELECT MAX(version) AS version FROM schema_migrations").await?
                .into_iter().next().map(|row| n(&row, "version")).unwrap_or(0);
            if version != latest {
                return Err(format!("migration {} is not the latest recorded version ({})", version, latest));
            }
            target.exec(&format!("DELETE FROM schema_migrations WHERE version={}", version)).await?;
            Ok(format!("migration {} removed from the ledger; the next apply runs it again", version))
        }
        Repair::AcceptChecksum(_) => {
            if stored.is_empty() {
                return Err(format!("migration {} predates checksums; its legacy history stays unverified", version));
            }
            if stored == "squashed" {
                return Err(format!("migration {} is covered by the consolidated baseline; the squash marker is not a drifted checksum", version));
            }
            let checksum = checksum(migration.sql);
            target.exec(&format!("UPDATE schema_migrations SET checksum='{}' WHERE version={}", checksum, version)).await?;
            Ok(format!("migration {} now records checksum {}", version, checksum))
        }
    }
}

/// Verify the ledger without modifying anything.
pub fn check(rows: &[LedgerRow], migrations: &[Migration]) -> Vec<Problem> {
    let latest = migrations.last().map(|m| m.version).unwrap_or(0);
    let mut problems = Vec::new();
    let max_applied = rows.iter().map(|r| r.version).max().unwrap_or(0);
    // A database migrated by a newer binary is fatal on its own; listing every
    // version as a gap would only obscure the reason.
    if max_applied > latest {
        return vec![Problem::Newer { version: max_applied, latest }];
    }
    for row in rows {
        let Some(migration) = migrations.iter().find(|m| m.version == row.version) else {
            problems.push(Problem::Unknown { version: row.version });
            continue;
        };
        if !row.success {
            problems.push(Problem::Incomplete { version: row.version });
        } else if !row.checksum.is_empty() && (if row.checksum == "squashed" {
            !(2..=SQUASHED_THROUGH).contains(&row.version)
        } else { row.checksum != checksum(migration.sql) }) {
            problems.push(Problem::Checksum { version: row.version });
        }
    }
    // A later version may only be applied when every earlier one is.
    if max_applied > 0 {
        for migration in migrations.iter().filter(|m| m.version <= max_applied) {
            if !rows.iter().any(|row| row.version == migration.version) {
                problems.push(Problem::Gap { version: migration.version });
            }
        }
    }
    problems
}

pub fn validate(migrations: &[Migration]) -> Result<(), String> {
    if migrations.is_empty() { return Err("migration manifest is empty".to_string()); }
    let mut names = BTreeSet::new();
    for (index, migration) in migrations.iter().enumerate() {
        if migration.version != index as i64 + 1 {
            return Err(format!("migration versions must run 1.. in order; found {} at position {}", migration.version, index + 1));
        }
        if migration.name.is_empty() || migration.sql.trim().is_empty() {
            return Err(format!("migration {} has no name or SQL", migration.version));
        }
        if !names.insert(migration.name) {
            return Err(format!("duplicate migration name {}", migration.name));
        }
    }
    let latest = migrations.last().map(|m| m.version).unwrap_or(0);
    if SQUASHED_THROUGH > latest {
        return Err(format!("squashed baseline covers version {} but the manifest ends at {}", SQUASHED_THROUGH, latest));
    }
    Ok(())
}

pub fn checksum(sql: &str) -> String {
    let digest = Sha256::digest(sql.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest { let _ = write!(out, "{:02x}", byte); }
    out
}

fn sql_literal(value: &str) -> String { value.replace('\'', "''") }

pub fn all_statements() -> Vec<String> {
    MIGRATIONS.iter().flat_map(|migration| split_sql(migration.sql)).collect()
}

/// Split using the legacy profile, including SQLite bracket identifiers.
pub fn split_sql(sql: &str) -> Vec<String> { split_sql_with_dialect(sql, SqlDialect::Legacy) }

/// Split a migration into single statements. Handles quoted strings, quoted
/// identifiers, line and block comments, PostgreSQL dollar quoting, and the
/// body of `CREATE TRIGGER`, whose internal semicolons do not end the statement.
pub fn split_sql_with_dialect(sql: &str, dialect: SqlDialect) -> Vec<String> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mode { Normal, Single, Double, Backtick, Bracket, Line, Block }
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut mode = Mode::Normal;
    let mut single_backslash_escape = false;
    let mut continuation = false;
    let mut continuation_newline = false;
    let mut dollar: Option<&[u8]> = None;
    let mut has_code = false;
    let mut words = 0;
    let mut create = false;
    let mut create_temp = false;
    let mut trigger = false;
    let mut trigger_depth = 0usize;

    while index < bytes.len() {
        if let Some(tag) = dollar {
            if bytes[index..].starts_with(tag) { index += tag.len(); dollar = None; } else { index += 1; }
            continue;
        }
        let byte = bytes[index];
        match mode {
            Mode::Normal => {
                if continuation {
                    if byte == b'\n' || byte == b'\r' { continuation_newline = true; }
                    else if !(byte.is_ascii_whitespace() || byte == b'\''
                        || (byte == b'-' && bytes.get(index + 1) == Some(&b'-'))
                        || (byte == b'/' && bytes.get(index + 1) == Some(&b'*'))) { continuation = false; }
                }
                if byte == b'\'' {
                    single_backslash_escape = matches!(dialect, SqlDialect::Legacy | SqlDialect::Mysql)
                        || (dialect == SqlDialect::Postgres && ((continuation && continuation_newline && single_backslash_escape)
                            || (index > 0 && matches!(bytes[index - 1], b'E' | b'e')
                                && (index < 2 || !(bytes[index - 2].is_ascii_alphanumeric() || bytes[index - 2] == b'_' || bytes[index - 2] == b'$' || !bytes[index - 2].is_ascii())))));
                    continuation = false;
                    mode = Mode::Single; has_code = true; index += 1;
                }
                else if byte == b'"' { mode = Mode::Double; has_code = true; index += 1; }
                else if byte == b'`' { mode = Mode::Backtick; has_code = true; index += 1; }
                else if byte == b'[' && matches!(dialect, SqlDialect::Legacy | SqlDialect::Sqlite) { mode = Mode::Bracket; has_code = true; index += 1; }
                else if byte == b'-' && bytes.get(index + 1) == Some(&b'-') { mode = Mode::Line; index += 2; }
                else if byte == b'#' && matches!(dialect, SqlDialect::Legacy | SqlDialect::Mysql) { mode = Mode::Line; index += 1; }
                else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') { mode = Mode::Block; index += 2; }
                else if byte == b'$' {
                    match dollar_tag(bytes, index) {
                        Some(tag) => { dollar = Some(tag); index += tag.len(); has_code = true; }
                        None => { index += 1; }
                    }
                } else if byte.is_ascii_alphabetic() || byte == b'_' {
                    let word_start = index;
                    index += 1;
                    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_' || bytes[index] == b'$') { index += 1; }
                    let word = &sql[word_start..index];
                    if words == 0 { create = word.eq_ignore_ascii_case("CREATE"); }
                    if words == 1 && create {
                        trigger = word.eq_ignore_ascii_case("TRIGGER");
                        create_temp = word.eq_ignore_ascii_case("TEMP") || word.eq_ignore_ascii_case("TEMPORARY");
                    }
                    if words == 2 && create && create_temp { trigger = word.eq_ignore_ascii_case("TRIGGER"); }
                    words += 1;
                    if trigger && (word_start == 0 || bytes[word_start - 1] != b'.') {
                        if word.eq_ignore_ascii_case("BEGIN") || (trigger_depth > 0 && word.eq_ignore_ascii_case("CASE")) {
                            trigger_depth += 1;
                        } else if trigger_depth > 0 && word.eq_ignore_ascii_case("END") {
                            trigger_depth -= 1;
                        }
                    }
                    has_code = true;
                } else if byte == b';' {
                    if trigger_depth > 0 { index += 1; continue; }
                    push_statement(&mut out, &sql[start..index], has_code, dialect);
                    start = index + 1;
                    has_code = false;
                    words = 0;
                    create = false;
                    create_temp = false;
                    trigger = false;
                    index += 1;
                } else {
                    if !byte.is_ascii_whitespace() { has_code = true; }
                    index += 1;
                }
            }
            Mode::Single => {
                if single_backslash_escape && byte == b'\\' && index + 1 < bytes.len() { index += 2; }
                else if byte == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') { index += 2; } else {
                        mode = Mode::Normal; index += 1;
                        continuation = dialect == SqlDialect::Postgres;
                        continuation_newline = false;
                    }
                } else { index += 1; }
            }
            Mode::Double => {
                if byte == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') { index += 2; } else { mode = Mode::Normal; index += 1; }
                } else { index += 1; }
            }
            Mode::Backtick => {
                if byte == b'`' { mode = Mode::Normal; }
                index += 1;
            }
            Mode::Bracket => {
                if byte == b']' { mode = Mode::Normal; }
                index += 1;
            }
            Mode::Line => {
                if byte == b'\n' || (dialect == SqlDialect::Postgres && byte == b'\r') {
                    if continuation { continuation_newline = true; }
                    mode = Mode::Normal;
                }
                index += 1;
            }
            Mode::Block => {
                if continuation && (byte == b'\n' || byte == b'\r') { continuation_newline = true; }
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') { mode = Mode::Normal; index += 2; } else { index += 1; }
            }
        }
    }
    push_statement(&mut out, &sql[start..], has_code, dialect);
    out
}

fn push_statement(out: &mut Vec<String>, text: &str, has_code: bool, dialect: SqlDialect) {
    if !has_code { return; }
    let statement = trim_leading_comments(text, dialect).trim_end();
    if statement.is_empty() { return; }
    out.push(statement.to_string());
}

/// Drop leading line and block comments so a statement starts with its first
/// keyword. Backend rewriting (for example MySQL DDL) keys off that word.
fn trim_leading_comments(text: &str, dialect: SqlDialect) -> &str {
    let mut rest = text.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            match after.find(|c| c == '\n' || (dialect == SqlDialect::Postgres && c == '\r')) {
                Some(index) => rest = after[index + 1..].trim_start(), None => return ""
            }
        } else if let Some(after) = rest.strip_prefix('#').filter(|_| matches!(dialect, SqlDialect::Legacy | SqlDialect::Mysql)) {
            match after.find('\n') { Some(index) => rest = after[index + 1..].trim_start(), None => return "" }
        } else if let Some(after) = rest.strip_prefix("/*") {
            match after.find("*/") { Some(index) => rest = after[index + 2..].trim_start(), None => return "" }
        } else {
            return rest;
        }
    }
}

/// PostgreSQL dollar quote opener at `at`, including both `$` characters.
fn dollar_tag(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let mut end = at + 1;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') { end += 1; }
    if end >= bytes.len() || bytes[end] != b'$' { return None; }
    // `$1` is a placeholder, not a quote opener.
    if end > at + 1 && bytes[at + 1].is_ascii_digit() { return None; }
    // Tags are short; refuse absurd runs so a stray '$' cannot scan the file.
    if end - at > 64 { return None; }
    Some(&bytes[at..=end])
}

struct Lock<'a, T: Target> { target: &'a T, owner: String }

impl<'a, T: Target> Lock<'a, T> {
    async fn acquire(target: &'a T) -> Result<Self, String> {
        let owner = openwarp_crypto::random_token("mig");
        let now = crate::clock::now();
        // Two attempts cover the case where the previous holder released
        // between our insert and our read.
        for attempt in 0..2 {
            if target.exec(&format!(
                "INSERT INTO schema_migration_lock(id,owner,acquired_at) VALUES(1,'{}',{})", owner, now,
            )).await.is_ok() {
                return Ok(Self { target, owner });
            }
            let holder = target.query("SELECT owner, acquired_at FROM schema_migration_lock WHERE id=1").await?
                .into_iter().next();
            let Some(holder) = holder else {
                if attempt == 0 { continue; }
                return Err("could not acquire the migration lock; retry".to_string());
            };
            if s(&holder, "owner") == NATIVE_PROTOCOL {
                return Err("database uses native-session-v1 migration ownership; this permanent protocol marker is not an active lock. Use Db apply/repair or an explicitly forwarding target".to_string());
            }
            return Err(format!(
                "another instance is applying migrations (owner {:?}, held since {}); ownership never expires. Quiesce all runners before owner-qualified recovery",
                s(&holder, "owner"), n(&holder, "acquired_at"),
            ));
        }
        Err("could not acquire the migration lock; retry".to_string())
    }

    async fn release(&self) {
        let _ = self.target.exec(&format!(
            "DELETE FROM schema_migration_lock WHERE id=1 AND owner='{}'", sql_literal(&self.owner),
        )).await;
    }
}

async fn ensure_ledger<T: Target>(target: &T) -> Result<(), String> {
    exec_idempotent(target, "CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL,name TEXT DEFAULT '',checksum TEXT DEFAULT '',success BIGINT DEFAULT 1,execution_ms BIGINT DEFAULT 0)").await?;
    // A ledger created by an older binary lacks the metadata columns. Adding
    // them is the one place duplicates are expected, so a duplicate is ignored
    // and every other error still aborts boot.
    for column in [
        "ALTER TABLE schema_migrations ADD COLUMN name TEXT DEFAULT ''",
        "ALTER TABLE schema_migrations ADD COLUMN checksum TEXT DEFAULT ''",
        "ALTER TABLE schema_migrations ADD COLUMN success BIGINT DEFAULT 1",
        "ALTER TABLE schema_migrations ADD COLUMN execution_ms BIGINT DEFAULT 0",
    ] {
        exec_idempotent(target, column).await?;
    }
    Ok(())
}

async fn ensure_lock_table<T: Target>(target: &T) -> Result<(), String> {
    exec_idempotent(target, "CREATE TABLE IF NOT EXISTS schema_migration_lock(id BIGINT PRIMARY KEY,owner TEXT NOT NULL,acquired_at BIGINT NOT NULL)").await
}

/// Create or alter an object that another booting instance may be creating at
/// the same time. An existing object is success; a PostgreSQL catalogue race is
/// retried once so the other transaction's change can settle.
async fn exec_idempotent<T: Target>(target: &T, sql: &str) -> Result<(), String> {
    match target.exec(sql).await {
        Ok(()) => Ok(()),
        Err(error) if is_transient(&error) => match target.exec(sql).await {
            Ok(()) => Ok(()),
            Err(again) if is_duplicate(&again) => Ok(()),
            Err(again) => Err(again),
        },
        Err(error) if is_duplicate(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn is_transient(error: &str) -> bool {
    let message = error.to_ascii_lowercase();
    message.contains("duplicate key value violates unique constraint") || message.contains("tuple concurrently updated")
}

#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> i64 { js_sys::Date::now() as i64 }

/// Poll a future that is known never to yield. The Durable Object constructor
/// cannot await, and every storage call in that path returns immediately.
#[cfg(target_arch = "wasm32")]
pub fn wait<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { RawWaker::new(std::ptr::null(), &VTABLE) }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let mut spins = 0;
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                spins += 1;
                assert!(spins < 100_000, "migration future yielded inside the Durable Object constructor");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_contiguous_and_named() { validate(MIGRATIONS).expect("manifest"); }

    #[test]
    fn split_keeps_quoted_and_dollar_quoted_semicolons() {
        let sql = "CREATE TABLE t(a TEXT DEFAULT 'x;y'); -- trailing ; comment\n\
                   INSERT INTO t VALUES('it''s; fine');\n\
                   /* block ; */ UPDATE t SET a=$tag$body;still$tag$;\n";
        let statements = split_sql(sql);
        assert_eq!(statements.len(), 3, "{:#?}", statements);
        assert!(statements[0].contains("'x;y'"));
        assert!(statements[1].contains("'it''s; fine'"));
        assert!(statements[2].contains("$tag$body;still$tag$"));
    }

    #[test]
    fn split_drops_comment_only_tail() {
        assert_eq!(split_sql("-- nothing here\n").len(), 0);
        assert_eq!(split_sql("SELECT 1; -- done\n").len(), 1);
    }

    #[test]
    fn split_keeps_trigger_bodies_together() {
        let sql = "CREATE TRIGGER t AFTER INSERT ON x BEGIN UPDATE y SET a=1; UPDATE y SET b=2; END;\nSELECT 1;";
        let statements = split_sql(sql);
        assert_eq!(statements.len(), 2, "{:#?}", statements);
        assert!(statements[0].trim_end().ends_with("END"));
    }

    #[test]
    fn checksum_is_stable_hex() {
        assert_eq!(checksum("a").len(), 64);
        assert_eq!(checksum("a"), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
        assert_ne!(checksum("a"), checksum("a "));
    }

    #[test]
    fn duplicate_versions_fail_validation() {
        let broken = [
            Migration { version: 1, name: "a", sql: "SELECT 1;", tolerant: false },
            Migration { version: 1, name: "b", sql: "SELECT 1;", tolerant: false },
        ];
        assert!(validate(&broken).is_err());
    }

    #[test]
    fn check_reports_drift_newer_and_gaps() {
        let migrations = MIGRATIONS;
        let rows = vec![
            LedgerRow { version: 1, name: "baseline".into(), checksum: "legacy".into(), success: true, execution_ms: 0 },
            LedgerRow { version: 2, name: "token_scopes".into(), checksum: "not-the-checksum".into(), success: true, execution_ms: 0 },
            LedgerRow { version: 4, name: "instance_leases".into(), checksum: String::new(), success: true, execution_ms: 0 },
        ];
        let problems = check(&rows, migrations);
        assert!(problems.contains(&Problem::Checksum { version: 2 }));
        assert!(problems.contains(&Problem::Gap { version: 3 }));
        let newer = vec![LedgerRow { version: 99, name: String::new(), checksum: String::new(), success: true, execution_ms: 0 }];
        // Read the newest shipped version instead of pinning it, so appending a
        // migration does not turn this assertion into a stale constant.
        let latest = migrations.last().map(|m| m.version).unwrap_or(0);
        assert_eq!(check(&newer, migrations), vec![Problem::Newer { version: 99, latest }]);
    }

    #[test]
    fn check_reports_interrupted_migration() {
        let rows = vec![LedgerRow { version: 18, name: "env_restricted_backfill".into(), checksum: checksum(MIGRATIONS[17].sql), success: false, execution_ms: 0 }];
        let problems = check(&rows, MIGRATIONS);
        assert!(problems.contains(&Problem::Incomplete { version: 18 }));
    }
}
