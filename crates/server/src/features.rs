//! Enterprise add-ons, each behind a Cargo feature and a per-workspace grant.
//!
//! Two independent decisions have to agree before one of these surfaces exists
//! for a request: the binary must have been built with the feature (otherwise
//! there is no route and no handler at all), and the workspace must hold a
//! grant for it. Compile time decides what is possible; the grant decides what
//! is allowed. A future subscription check belongs in the same place as the
//! grant lookup, not in the handlers.

/// Every gated surface, in the order the console lists them.
pub const NAMES: &[&str] = &[
    "saml",
    "scim",
    "pki",
    "ssh-ca",
    "transit",
    "workload-identity",
    "change-requests",
    "ldap",
];

/// Whether this binary was built with the surface.
// The `matches!` rewrite clippy suggests would drop the per-arm cfg checks.
#[allow(clippy::match_like_matches_macro)]
pub fn compiled(name: &str) -> bool {
    match name {
        "saml" => cfg!(feature = "saml"),
        "scim" => cfg!(feature = "scim"),
        "pki" => cfg!(feature = "pki"),
        "ssh-ca" => cfg!(feature = "ssh-ca"),
        "transit" => cfg!(feature = "transit"),
        "workload-identity" => cfg!(feature = "workload-identity"),
        "change-requests" => cfg!(feature = "change-requests"),
        "ldap" => cfg!(feature = "ldap"),
        _ => false,
    }
}

pub fn known(name: &str) -> bool { NAMES.contains(&name) }

/// The surfaces this binary can offer. Unknown names are rejected on write, so
/// a grant row cannot smuggle in a name the build does not know.
pub fn compiled_names() -> Vec<&'static str> { NAMES.iter().copied().filter(|n| compiled(n)).collect() }

/// Keeps only known and compiled names, preserving request order.
pub fn normalize<'a, I: IntoIterator<Item = &'a str>>(names: I) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = Vec::new();
    for n in names {
        if known(n) && compiled(n) && !out.contains(&n) { out.push(n); }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_uncompiled_names_are_dropped() {
        assert!(normalize(["not-a-feature"]).is_empty());
        // A name that is not in the build is dropped even though it is known.
        let listed = normalize(["saml", "saml", "nope"]);
        assert!(listed.len() <= 1);
        assert!(listed.iter().all(|n| known(n) && compiled(n)));
    }

    #[test]
    fn names_are_unique_and_known() {
        let mut seen = std::collections::HashSet::new();
        for n in NAMES { assert!(seen.insert(*n), "duplicate feature name {}", n); assert!(known(n)); }
        assert!(compiled_names().iter().all(|n| compiled(n)));
    }
}
