use openwarp_server::integrations::validate_rotation_config;
use serde_json::{json, Value};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct AllowedHosts(Option<String>);
impl AllowedHosts {
    fn set(value: &str) -> Self {
        let old = std::env::var("OPENWARP_ALLOWED_DB_HOSTS").ok();
        std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", value);
        Self(old)
    }
}
impl Drop for AllowedHosts {
    fn drop(&mut self) {
        match &self.0 {
            Some(value) => std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", value),
            None => std::env::remove_var("OPENWARP_ALLOWED_DB_HOSTS"),
        }
    }
}

fn config(connection: &str) -> Value {
    json!({"kind":"postgres-static", "connection":connection, "username":"app_login"})
}

#[test]
fn postgres_static_accepts_complete_config_without_connecting() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _hosts = AllowedHosts::set("db.example.invalid");
    assert!(validate_rotation_config(&config("postgres://admin:pw@db.example.invalid/db")).is_ok(),
        "a complete allowlisted postgres-static configuration must be supported");
}

#[test]
fn postgres_static_checks_the_driver_host_not_the_url_authority() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _hosts = AllowedHosts::set("db.example.invalid");
    assert!(validate_rotation_config(&config("postgres://admin:pw@db.example.invalid/db")).is_ok(),
        "positive control: the adapter must exist before rejection tests are meaningful");
    for connection in [
        "postgres://admin:pw@forbidden.example.invalid/db",
        "postgres://admin:pw@db.example.invalid/db?host=forbidden.example.invalid",
        "postgres://admin:pw@db.example.invalid/db?host=127.0.0.1",
        "postgres://admin:pw@db.example.invalid.evil.invalid/db",
    ] {
        assert!(validate_rotation_config(&config(connection)).is_err(), "accepted non-allowlisted driver host: {connection}");
    }
}

#[test]
fn postgres_static_requires_explicit_allowlist_and_complete_credentials() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _hosts = AllowedHosts::set("db.example.invalid");
    let valid = config("postgres://admin:pw@db.example.invalid/db");
    assert!(validate_rotation_config(&valid).is_ok(), "positive control: postgres-static is supported");
    for field in ["username", "connection"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(validate_rotation_config(&missing).is_err(), "missing {field} accepted");
        let mut empty = valid.clone();
        empty[field] = json!("");
        assert!(validate_rotation_config(&empty).is_err(), "empty {field} accepted");
    }
    std::env::set_var("OPENWARP_ALLOWED_DB_HOSTS", "");
    assert!(validate_rotation_config(&valid).is_err(), "an empty allowlist must not authorize database access");
}
