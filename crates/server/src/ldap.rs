//! LDAP directory sign-in.
//!
//! Unlike OIDC and SAML, the directory hands the user's password to this
//! server, so the wire is always TLS: only `ldaps://` is accepted and the bind
//! password is never sent over a plaintext connection. A service account
//! searches for the entry, then a second connection binds as that entry with
//! the supplied password; only a successful bind authenticates.

use std::collections::BTreeSet;
use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

pub struct DirectoryConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub user_filter: String,
    pub email_attr: String,
    pub name_attr: String,
    pub group_attr: String,
    pub group_roles: String,
    pub ca_cert_pem: String,
    pub allowed_domains: String,
}

pub struct DirectoryUser {
    pub dn: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
}

#[derive(Debug)]
pub enum DirectoryError {
    Denied,
    Ambiguous,
    Unavailable(String),
}

// RFC 4515: a literal `*`, `(`, `)`, `\` or NUL in the value would otherwise
// change the filter's structure, which is how LDAP injection works.
pub fn escape_filter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

pub fn build_filter(template: &str, username: &str) -> Result<String, String> {
    if !template.contains("{username}") {
        return Err("user_filter must contain {username}".into());
    }
    if username.trim().is_empty() || username.contains('\0') {
        return Err("username is not valid".into());
    }
    Ok(template.replace("{username}", &escape_filter(username)))
}

// Only LDAPS: an `ldap://` URL would put the service password and the user's
// password on the wire in clear text. STARTTLS is not attempted.
pub fn url_ok(url: &str) -> bool {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("ldaps://") || url.chars().any(char::is_whitespace) {
        return false;
    }
    let rest = &url["ldaps://".len()..];
    if rest.contains('@') {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !host.starts_with(':')
}

pub fn valid_attr(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn valid_role_name(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 64
        && role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// The directory asserts the address; local syntax validation only stops a
// malformed attribute from creating an unusable account.
pub fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else { return false };
    !local.is_empty() && !domain.is_empty() && !email.contains(char::is_whitespace)
        && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        && email.len() <= 254
}

// Mapping syntax is `Group=role;Other Group=role`. The group part is matched
// case-insensitively against the whole attribute value and against each RDN
// value, so `CN=Admins,OU=Groups,DC=example` matches `Admins`.
pub fn valid_mapping(mapping: &str) -> bool {
    if mapping.trim().is_empty() {
        return true;
    }
    mapping.split(';').filter(|p| !p.trim().is_empty()).all(|pair| match pair.rsplit_once('=') {
        Some((group, role)) => !group.trim().is_empty() && valid_role_name(role.trim()),
        None => false,
    })
}

pub fn mapping_role(mapping: &str, groups: &[String]) -> Option<String> {
    for pair in mapping.split(';') {
        let Some((group, role)) = pair.rsplit_once('=') else { continue };
        let group = group.trim();
        let role = role.trim();
        if group.is_empty() || role.is_empty() {
            continue;
        }
        if groups.iter().any(|value| group_matches(group, value)) {
            return Some(role.to_string());
        }
    }
    None
}

fn group_matches(pattern: &str, value: &str) -> bool {
    if pattern.eq_ignore_ascii_case(value) {
        return true;
    }
    // Only the entry's own RDN names the group. Matching parent OUs would give
    // `Admins=admin` to every member of a OU=Admins subtree.
    let rdn = value.split(',').next().unwrap_or(value);
    let name = rdn.split_once('=').map(|(_, v)| v.trim().trim_matches('"')).unwrap_or_else(|| rdn.trim());
    !name.is_empty() && pattern.eq_ignore_ascii_case(name)
}

pub async fn authenticate(cfg: &DirectoryConfig, username: &str, password: &str) -> Result<DirectoryUser, DirectoryError> {
    // An empty password is an unauthenticated bind, which many servers accept
    // for any DN. It must never reach the wire.
    if username.trim().is_empty() || password.is_empty() || password.contains('\0') {
        return Err(DirectoryError::Denied);
    }
    let filter = build_filter(&cfg.user_filter, username).map_err(DirectoryError::Unavailable)?;
    let settings = settings(cfg)?;

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings.clone(), &cfg.url)
        .await
        .map_err(|e| DirectoryError::Unavailable(format!("directory connection failed: {}", e)))?;
    ldap3::drive!(conn);
    let bound = ldap
        .simple_bind(&cfg.bind_dn, &cfg.bind_password)
        .await
        .map_err(|e| DirectoryError::Unavailable(format!("service bind failed: {}", e)))?;
    if bound.rc != 0 {
        let _ = ldap.unbind().await;
        return Err(DirectoryError::Unavailable(format!(
            "the directory refused the service account (result code {}); check bind_dn and bind_password",
            bound.rc
        )));
    }

    let attrs: Vec<String> = [&cfg.email_attr, &cfg.name_attr, &cfg.group_attr]
        .into_iter()
        .filter(|a| !a.is_empty())
        .cloned()
        .collect();
    // Two matches already mean ambiguity. Ask the directory to stop after two
    // entries and stop reading after two regardless, so a directory that
    // ignores the limit cannot make this process buffer a whole result set.
    ldap.with_search_options(ldap3::SearchOptions::new().sizelimit(2).timelimit(10));
    let mut stream = ldap
        .streaming_search(&cfg.base_dn, Scope::Subtree, &filter, attrs)
        .await
        .map_err(|e| DirectoryError::Unavailable(format!("directory search failed: {}", e)))?;
    let mut entries = Vec::new();
    while entries.len() < 2 {
        match stream.next().await {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => break,
            Err(e) => return Err(DirectoryError::Unavailable(format!("directory search failed: {}", e))),
        }
    }
    let result = stream.finish().await;
    let _ = ldap.unbind().await;
    if result.rc != 0 {
        return Err(DirectoryError::Unavailable(format!("directory search failed (result code {})", result.rc)));
    }
    if entries.len() > 1 {
        return Err(DirectoryError::Ambiguous);
    }
    let Some(raw) = entries.into_iter().next() else { return Err(DirectoryError::Denied) };
    // SearchEntry::construct panics on malformed BER; a directory that answers
    // with junk must not take the request task down with it.
    let entry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| SearchEntry::construct(raw)))
        .map_err(|_| DirectoryError::Unavailable("the directory returned a malformed entry".into()))?;
    if entry.dn.is_empty() {
        return Err(DirectoryError::Unavailable("the directory returned an entry without a DN".into()));
    }

    let email = attr_first(&entry, &cfg.email_attr).unwrap_or_default().trim().to_ascii_lowercase();
    let name = attr_first(&entry, &cfg.name_attr).unwrap_or_default();
    let groups = attr_values(&entry, &cfg.group_attr);
    let user = DirectoryUser { dn: entry.dn, email, name, groups };

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &cfg.url)
        .await
        .map_err(|e| DirectoryError::Unavailable(format!("directory connection failed: {}", e)))?;
    ldap3::drive!(conn);
    let check = ldap
        .simple_bind(&user.dn, password)
        .await
        .map_err(|e| DirectoryError::Unavailable(format!("directory bind failed: {}", e)))?;
    let _ = ldap.unbind().await;
    match check.rc {
        0 => Ok(user),
        49 => Err(DirectoryError::Denied),
        rc => Err(DirectoryError::Unavailable(format!("the directory rejected the bind (result code {})", rc))),
    }
}

fn settings(cfg: &DirectoryConfig) -> Result<LdapConnSettings, DirectoryError> {
    let mut settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(8));
    if !cfg.ca_cert_pem.trim().is_empty() {
        let cert = native_tls::Certificate::from_pem(cfg.ca_cert_pem.as_bytes())
            .map_err(|e| DirectoryError::Unavailable(format!("ca_cert_pem is not a PEM certificate: {}", e)))?;
        let connector = native_tls::TlsConnector::builder()
            .add_root_certificate(cert)
            .build()
            .map_err(|e| DirectoryError::Unavailable(format!("TLS connector failed: {}", e)))?;
        settings = settings.set_connector(connector);
    }
    Ok(settings)
}

fn attr_values(entry: &SearchEntry, name: &str) -> Vec<String> {
    if name.is_empty() {
        return vec![];
    }
    entry
        .attrs
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn attr_first(entry: &SearchEntry, name: &str) -> Option<String> {
    attr_values(entry, name).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_values_are_escaped() {
        assert_eq!(escape_filter("a*b(c)d\\e"), "a\\2ab\\28c\\29d\\5ce");
        let filter = build_filter("(uid={username})", "*)(uid=*").unwrap();
        assert_eq!(filter, "(uid=\\2a\\29\\28uid=\\2a)");
    }

    #[test]
    fn filter_requires_a_placeholder() {
        assert!(build_filter("(uid=admin)", "x").is_err());
        assert!(build_filter("(uid={username})", " ").is_err());
    }

    #[test]
    fn only_ldaps_urls_are_accepted() {
        assert!(url_ok("ldaps://dir.example.com"));
        assert!(url_ok("ldaps://dir.example.com:3269"));
        assert!(!url_ok("ldap://dir.example.com"));
        assert!(!url_ok("ldaps://user@dir.example.com"));
        assert!(!url_ok("ldaps://"));
        assert!(!url_ok("https://dir.example.com"));
    }

    #[test]
    fn mapping_syntax_is_validated() {
        assert!(valid_mapping(""));
        assert!(valid_mapping("Admins=admin;Developers=developer"));
        assert!(!valid_mapping("Admins"));
        assert!(!valid_mapping("=admin"));
        assert!(!valid_mapping("Admins=bad role!"));
    }

    #[test]
    fn groups_match_by_dn_or_rdn() {
        let groups = vec!["CN=Admins,OU=Groups,DC=example,DC=com".to_string()];
        assert_eq!(mapping_role("Admins=admin", &groups).as_deref(), Some("admin"));
        assert_eq!(
            mapping_role("cn=admins,ou=groups,dc=example,dc=com=developer", &groups).as_deref(),
            Some("developer")
        );
        assert!(mapping_role("Developers=developer", &groups).is_none());
        // Parent OUs must not name the group.
        let nested = vec!["CN=Readers,OU=Admins,DC=example,DC=com".to_string()];
        assert!(mapping_role("Admins=admin", &nested).is_none());
    }
}
