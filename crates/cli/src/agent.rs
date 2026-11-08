use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

fn render(template: &str, secrets: &[Value]) -> Result<String, String> {
    let mut result = String::new(); let mut rest = template;
    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail.find("}}").ok_or("unclosed template expression")?;
        let reference = tail[..end].trim().strip_prefix("secret ").ok_or("only {{secret /path/KEY}} expressions are supported")?.trim();
        if !reference.starts_with('/') || reference.chars().any(char::is_control) { return Err("secret references must be absolute paths without control characters".into()); }
        let (folder, key) = reference.rsplit_once('/').ok_or("secret reference needs a key")?;
        let folder = format!("{}/", folder);
        if key.is_empty() || folder.contains("//") || folder.split('/').any(|s| s == "." || s == "..") { return Err("secret reference is not canonical".into()); }
        let mut found = secrets.iter().filter(|s| s["path"].as_str() == Some(&folder) && s["key"].as_str() == Some(key));
        let secret = found.next().ok_or("template references an unavailable secret")?;
        if found.next().is_some() { return Err("template reference is ambiguous".into()); }
        if secret["type"].as_str() == Some("sealed") || secret["decrypt_error"].as_bool() == Some(true) { return Err("template references an unreadable secret".into()); }
        result.push_str(secret["value"].as_str().ok_or("template references an unreadable secret")?);
        rest = &tail[end + 2..];
    }
    result.push_str(rest); Ok(result)
}

fn write_output(path: &Path, content: &[u8]) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => return Err("agent output must be a regular file, not a symlink".into()),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
        _ => {}
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(".openwarp-{}", openwarp_crypto::random_token("render")));
    let result = (|| {
        let mut opts = OpenOptions::new(); opts.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
        let mut file = opts.open(&tmp).map_err(|e| e.to_string())?;
        file.write_all(content).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        // Recheck after writing. Rename replaces the directory entry, never the
        // target of a symlink introduced after this check.
        match fs::symlink_metadata(path) {
            Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err("agent output changed to a nonregular file".into()),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
        fs::rename(&tmp, path).map_err(|e| e.to_string())
    })();
    if result.is_err() { let _ = fs::remove_file(&tmp); }
    result
}

fn literal_loopback(host: &str) -> bool {
    host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Canonical identity even when the output does not exist yet.
fn canonical_path(path: &Path) -> Result<std::path::PathBuf, String> {
    if let Ok(p) = fs::canonicalize(path) { return Ok(p); }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| "agent path has no file name".to_string())?;
    Ok(fs::canonicalize(parent).map_err(|e| e.to_string())?.join(name))
}

#[allow(clippy::too_many_arguments)]
pub fn run(host: &str, token: &str, env: &str, template: &Path, output: &Path, interval: u64, cache_ttl: u64, once: bool) -> Result<(), String> {
    if interval == 0 || interval > 3600 || cache_ttl > 300 { return Err("interval must be 1-3600 seconds and cache TTL 0-300 seconds".into()); }
    if token.is_empty() { return Err("agent requires a token for the selected host".into()); }
    let mut url = reqwest::Url::parse(host).map_err(|_| "agent host is not a valid URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err("agent host must be an HTTP(S) URL without credentials, query or fragment".into());
    }
    // A bearer credential must not cross remote plaintext. The exception is a
    // literal loopback address, not a hostname such as localhost that DNS or
    // hosts files could point elsewhere.
    if url.scheme() == "http" && !literal_loopback(url.host_str().unwrap_or("")) {
        return Err("agent requires HTTPS unless the host is a literal loopback address".into());
    }
    // Refuse a template aliased as its own output before any fetch or write, so
    // an equivalent spelling or symlink cannot destroy the source file.
    if canonical_path(template)? == canonical_path(output)? {
        return Err("agent template and output must be different files".into());
    }
    let builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none());
    let builder = if url.scheme() == "http" { builder.no_proxy() } else { builder };
    let client = builder.build().map_err(|_| "agent HTTP client could not be created")?;
    url.path_segments_mut().map_err(|_| "host cannot contain path segments")?.pop_if_empty().extend(["api", "envs", env, "export"]);
    url.set_query(Some("base=1"));
    let mut cache: Option<(Instant, Vec<Value>)> = None;
    loop {
        if cache.as_ref().map(|(at, _)| at.elapsed() >= Duration::from_secs(cache_ttl)).unwrap_or(true) {
            // No disk cache or outage fallback: a failed refresh cannot extend
            // the period during which an earlier authorization is trusted.
            drop(cache.take());
            let response = client.get(url.clone()).bearer_auth(token).send().map_err(|_| "agent could not fetch secrets")?;
            if !response.status().is_success() { return Err(format!("agent export returned HTTP {}", response.status())); }
            let mut body = Vec::new();
            use std::io::Read;
            response.take(8 * 1024 * 1024 + 1).read_to_end(&mut body).map_err(|_| "agent export could not be read")?;
            if body.len() > 8 * 1024 * 1024 { return Err("agent export exceeds 8 MiB".into()); }
            let data: Value = serde_json::from_slice(&body).map_err(|_| "agent export is not JSON")?;
            cache = Some((Instant::now(), data["secrets"].as_array().ok_or("agent export has no secrets array")?.clone()));
        }
        let text = fs::read_to_string(template).map_err(|e| e.to_string())?;
        let rendered = render(&text, &cache.as_ref().ok_or("agent has no authorized secrets")?.1)?;
        write_output(output, rendered.as_bytes())?;
        if once { return Ok(()); }
        std::thread::sleep(Duration::from_secs(interval));
    }
}
