//! Account SSH key sync for clouds that keep no updatable secret store.
//!
//! Linode and DigitalOcean both accept a name and a public key when a key is
//! created, then refuse to change the key material. A changed value is deleted
//! and created again, which issues a new id, so anything already bound to the
//! old id loses it until it is rebuilt.
use serde_json::{json, Value};
use std::collections::HashMap;

#[cfg(not(target_arch = "wasm32"))]
fn http() -> crate::http::Client { crate::http::Client::builder().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| crate::http::Client::builder().build().expect("http client")) }
#[cfg(target_arch = "wasm32")]
fn http() -> crate::http::Client { crate::http::Client::new() }
fn cfg<'a>(c: &'a Value, k: &str) -> &'a str { c.get(k).and_then(|v| v.as_str()).unwrap_or("") }
fn base(c: &Value, default: &str) -> String { let b = cfg(c, "base_url"); if b.is_empty() { default.to_string() } else { b.trim_end_matches('/').to_string() } }
fn enc(s: &str) -> String { s.bytes().map(|b| match b { b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(), b => format!("%{:02X}", b) }).collect() }
async fn send(r: crate::http::RequestBuilder) -> Result<String, String> {
    let resp = r.send().await.map_err(|e| e.to_string())?;
    let status = resp.status(); let text = resp.text().await.unwrap_or_default();
    if status.is_success() { Ok(text) } else { Err(format!("HTTP {}: {}", status, text.chars().take(400).collect::<String>())) }
}
fn id_of(value: &Value) -> Option<String> { value.get("id").and_then(|v| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(str::to_string))).filter(|s| !s.is_empty()) }

pub fn public_key_error(name: &str, value: &str) -> Option<String> { public_key(name, value).err() }
fn public_key(name: &str, value: &str) -> Result<String, String> {
    let key = value.trim();
    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 2 || !matches!(parts[0], "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" | "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com") {
        return Err(format!("{:?} is not an OpenSSH public key (expected a single-line ssh-ed25519 or ssh-rsa key)", name));
    }
    Ok(key.to_string())
}

/// Only secrets marked `ssh_key` are synced. A generic secret is never sent to
/// an SSH key API, even when its value happens to look like a public key.
pub fn only_ssh_keys(secrets: &[(String, String, String)]) -> Vec<(String, String)> {
    secrets.iter().filter(|(_, _, kind)| kind == "ssh_key").map(|(k, v, _)| (k.clone(), v.clone())).collect()
}

fn named(config: &Value, secrets: &[(String, String)]) -> Vec<(String, String)> {
    let include: Vec<String> = config.get("include_keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let exclude: Vec<String> = config.get("exclude_keys").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    secrets.iter().filter(|(k, _)| (include.is_empty() || include.contains(k)) && !exclude.contains(k)).map(|(k, v)| {
        (crate::integrations::desired_name(config, k), v.clone())
    }).filter(|(n, _)| seen.insert(n.clone())).collect()
}

struct KeySync<'a> { provider: &'a str, token: &'a str, root: &'a str, name_field: &'a str, key_field: &'a str, by_name: &'a HashMap<String, (String, String)>, keys: &'a [(String, String)], previous_managed: &'a [String], mode: &'a str, dry: bool }
async fn sync_keys(s: KeySync<'_>) -> Result<(String, Vec<String>), String> {
    let KeySync { provider, token, root, name_field, key_field, by_name, keys, previous_managed, mode, dry } = s;
    let client = http();
    let (mut created, mut replaced, mut unchanged) = (0, 0, 0);
    if !dry {
        for (name, key) in keys {
            match by_name.get(name) {
                Some((_, current)) if current == key => unchanged += 1,
                Some((id, _)) => {
                    send(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(token)).await.map_err(|e| format!("{} replace {} failed while deleting the old key: {}", provider, name, e))?;
                    send(client.post(root).bearer_auth(token).json(&json!({name_field: name, key_field: key}))).await.map_err(|e| format!("{} replace {} deleted the old key but the new one was rejected: {}", provider, name, e))?;
                    replaced += 1;
                }
                None => { send(client.post(root).bearer_auth(token).json(&json!({name_field: name, key_field: key}))).await.map_err(|e| format!("{} create {} failed: {}", provider, name, e))?; created += 1; }
            }
        }
        if mode == "mirror" { for name in previous_managed { if keys.iter().any(|(n, _)| n == name) { continue; }
            if let Some((id, _)) = by_name.get(name) { send(client.delete(format!("{}/{}", root, enc(id))).bearer_auth(token)).await.map_err(|e| format!("{} delete {} failed: {}", provider, name, e))?; } } }
    } else { for (name, key) in keys { match by_name.get(name) { Some((_, current)) if current == key => unchanged += 1, Some(_) => replaced += 1, None => created += 1 } } }
    let deleted = previous_managed.iter().filter(|n| !keys.iter().any(|(d, _)| d == *n) && by_name.contains_key(*n)).count();
    let managed = keys.iter().map(|(n, _)| n.clone()).collect();
    Ok((format!("{} sync{}: ssh keys created={} replaced={} unchanged={} deleted={}", provider, if dry { " (dry-run)" } else { "" }, created, replaced, unchanged, deleted), managed))
}

fn mode_of<'a>(config: &'a Value, provider: &str) -> Result<&'a str, String> {
    match cfg(config, "mode") { "" | "upsert" => Ok("upsert"), "mirror" => Ok("mirror"), other => Err(format!("{} mode must be upsert or mirror (got {:?})", provider, other)) }
}
fn bearer(config: &Value, provider: &str) -> Result<String, String> {
    let token = cfg(config, "token");
    if token.is_empty() { return Err(format!("{} requires token", provider)); }
    Ok(token.to_string())
}
async fn paged(token: &str, url_for: impl Fn(i64) -> String, array_key: &str, provider: &str, done: impl Fn(&Value, i64) -> bool) -> Result<Vec<Value>, String> {
    let client = http(); let mut out = Vec::new(); let mut page = 1i64;
    loop {
        let text = send(client.get(url_for(page)).bearer_auth(token)).await.map_err(|e| format!("{} list SSH keys failed: {}", provider, e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("{} invalid SSH key list: {}", provider, e))?;
        let items = value.get(array_key).and_then(Value::as_array).cloned().unwrap_or_default();
        let count = items.len() as i64;
        out.extend(items);
        if count == 0 || done(&value, page) { break; }
        page += 1;
        if page > 100 { return Err(format!("{} SSH key list did not terminate", provider)); }
    }
    Ok(out)
}

pub async fn linode_list(config: &Value) -> Result<Vec<Value>, String> {
    let token = bearer(config, "Linode")?;
    let root = base(config, "https://api.linode.com/v4");
    paged(&token, |page| format!("{}/profile/sshkeys?page={}&page_size=100", root, page), "data", "Linode", |value, page| page >= value.get("pages").and_then(Value::as_i64).unwrap_or(1)).await
}
pub async fn linode_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let token = bearer(config, "Linode")?; let mode = mode_of(config, "linode")?;
    let keys: Vec<(String, String)> = named(config, secrets).iter().map(|(n, v)| public_key(n, v).map(|k| (n.clone(), k))).collect::<Result<_, _>>()?;
    let remote = linode_list(config).await?;
    let by_name: HashMap<String, (String, String)> = remote.iter().filter_map(|v| Some((v.get("label")?.as_str()?.to_string(), (id_of(v)?, v.get("ssh_key").and_then(Value::as_str).unwrap_or("").trim().to_string())))).collect();
    sync_keys(KeySync { provider: "Linode", token: &token, root: &format!("{}/profile/sshkeys", base(config, "https://api.linode.com/v4")), name_field: "label", key_field: "ssh_key", by_name: &by_name, keys: &keys, previous_managed, mode, dry: config.get("dry_run").and_then(Value::as_bool).unwrap_or(false) }).await
}
pub async fn linode_test(config: &Value) -> Result<String, String> {
    Ok(format!("Linode connection OK: {} SSH key(s) visible", linode_list(config).await?.len()))
}

pub async fn digitalocean_list(config: &Value) -> Result<Vec<Value>, String> {
    let token = bearer(config, "DigitalOcean SSH keys")?;
    let root = base(config, "https://api.digitalocean.com/v2");
    paged(&token, |page| format!("{}/account/keys?page={}&per_page=200", root, page), "ssh_keys", "DigitalOcean", |value, _| value.get("links").and_then(|l| l.get("pages")).and_then(|p| p.get("next")).and_then(Value::as_str).unwrap_or("").is_empty()).await
}
pub async fn digitalocean_sync(config: &Value, secrets: &[(String, String)], previous_managed: &[String]) -> Result<(String, Vec<String>), String> {
    let token = bearer(config, "DigitalOcean SSH keys")?; let mode = mode_of(config, "digitalocean_ssh")?;
    let keys: Vec<(String, String)> = named(config, secrets).iter().map(|(n, v)| public_key(n, v).map(|k| (n.clone(), k))).collect::<Result<_, _>>()?;
    let remote = digitalocean_list(config).await?;
    let by_name: HashMap<String, (String, String)> = remote.iter().filter_map(|v| Some((v.get("name")?.as_str()?.to_string(), (id_of(v)?, v.get("public_key").and_then(Value::as_str).unwrap_or("").trim().to_string())))).collect();
    sync_keys(KeySync { provider: "DigitalOcean", token: &token, root: &format!("{}/account/keys", base(config, "https://api.digitalocean.com/v2")), name_field: "name", key_field: "public_key", by_name: &by_name, keys: &keys, previous_managed, mode, dry: config.get("dry_run").and_then(Value::as_bool).unwrap_or(false) }).await
}
pub async fn digitalocean_test(config: &Value) -> Result<String, String> {
    Ok(format!("DigitalOcean connection OK: {} SSH key(s) visible", digitalocean_list(config).await?.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYQJZ7VR/OW5fqVOvmn+BRt5SLWDPx2UVO3ALmn21ZE openwarp-test";
    const KEY_NEW: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYQJZ7VR/OW5fqVOvmn+BRt5SLWDPx2UVO3ALmn21ZE replaced";

    fn header_end(buf: &[u8]) -> Option<usize> { buf.windows(4).position(|w| w == b"\r\n\r\n") }
    fn content_length(head: &str) -> usize { head.lines().find_map(|l| { let (k, v) = l.split_once(':')?; if k.eq_ignore_ascii_case("content-length") { v.trim().parse().ok() } else { None } }).unwrap_or(0) }
    type Calls = Arc<Mutex<Vec<(String, String, String)>>>;
    fn serve(routes: Vec<(String, u16, String)>) -> (String, Calls) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sink = calls.clone();
        std::thread::spawn(move || { for incoming in listener.incoming() {
            let mut stream = match incoming { Ok(s) => s, Err(_) => continue };
            let mut buf = Vec::new(); let mut chunk = [0u8; 4096];
            loop { let read = match stream.read(&mut chunk) { Ok(0) => break, Ok(n) => n, Err(_) => break }; buf.extend_from_slice(&chunk[..read]); if let Some(end) = header_end(&buf) { let head = String::from_utf8_lossy(&buf[..end]).to_string(); if buf.len() >= end + 4 + content_length(&head) { break; } } }
            let end = header_end(&buf).unwrap_or(buf.len()); let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let mut parts = head.lines().next().unwrap_or("").split_whitespace(); let method = parts.next().unwrap_or("").to_string(); let path = parts.next().unwrap_or("").to_string();
            let len = content_length(&head); let body = String::from_utf8_lossy(&buf[end + 4..(end + 4 + len).min(buf.len())]).to_string();
            sink.lock().unwrap().push((method.clone(), path.clone(), body.clone()));
            let key = format!("{} {} {}", method, path, body);
            let (status, payload) = match routes.iter().find(|(pattern, _, _)| key.contains(pattern)) { Some((_, status, body)) => (*status, body.clone()), None => (200, "{}".into()) };
            let line = match status { 201 => "201 Created", 204 => "204 No Content", _ => "200 OK" };
            let _ = stream.write_all(format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", line, payload.len(), payload).as_bytes());
        } });
        (format!("http://{}", addr), calls)
    }

    #[tokio::test]
    async fn linode_replaces_a_changed_key_and_ignores_other_secrets() {
        let listed = format!("{{\"data\":[{{\"id\":7,\"label\":\"OLD\",\"ssh_key\":\"{}\"}},{{\"id\":9,\"label\":\"DEPLOY\",\"ssh_key\":\"{}\"}}],\"page\":1,\"pages\":1,\"results\":2}}", KEY, KEY);
        let (base, calls) = serve(vec![
            ("GET /profile/sshkeys".into(), 200, listed),
            ("DELETE /profile/sshkeys/9".into(), 200, "{}".into()),
            ("DELETE /profile/sshkeys/7".into(), 200, "{}".into()),
            ("POST /profile/sshkeys".into(), 200, "{\"id\":11}".into()),
        ]);
        let config = json!({"base_url": base, "token": "linode-token", "mode": "mirror"});
        let (report, _) = linode_sync(&config, &ssh_keys_only(&[("DEPLOY", KEY_NEW, "ssh_key"), ("PLAIN", "not-a-key", "secret")]), &["OLD".into()]).await.expect("linode");
        assert!(report.contains("replaced=1") && report.contains("deleted=1"), "{}", report);
        let calls = calls.lock().unwrap();
        assert!(calls.iter().any(|(m, p, body)| m == "POST" && p == "/profile/sshkeys" && body.contains("\"label\":\"DEPLOY\"")), "the new key is created by label");
        assert!(!calls.iter().any(|(_, _, body)| body.contains("PLAIN")), "a generic secret must not reach an SSH key API");
    }

    fn ssh_keys_only(items: &[(&str, &str, &str)]) -> Vec<(String, String)> { only_ssh_keys(&items.iter().map(|(k, v, t)| (k.to_string(), v.to_string(), t.to_string())).collect::<Vec<_>>()) }

    #[test]
    fn ssh_key_names_follow_the_shared_prefix_and_suffix() {
        let config = json!({"_environment": "prod", "prefix": "APP_", "suffix": "_{{environment}}"});
        let keys = ssh_keys_only(&[("DEPLOY", KEY, "ssh_key"), ("PLAIN", KEY, "secret")]);
        assert_eq!(named(&config, &keys), vec![("APP_DEPLOY_prod".to_string(), KEY.to_string())]);
    }

    #[tokio::test]
    async fn digitalocean_recreates_a_changed_account_key() {
        let listed = format!("{{\"ssh_keys\":[{{\"id\":9,\"name\":\"DEPLOY\",\"public_key\":\"{}\"}}],\"links\":{{\"pages\":{{}}}},\"meta\":{{\"total\":1}}}}", KEY);
        let (base, calls) = serve(vec![
            ("GET /account/keys".into(), 200, listed),
            ("DELETE /account/keys/9".into(), 204, String::new()),
            ("POST /account/keys".into(), 201, "{\"ssh_key\":{\"id\":11}}".into()),
        ]);
        let config = json!({"base_url": base, "token": "do-token"});
        let (report, _) = digitalocean_sync(&config, &ssh_keys_only(&[("DEPLOY", KEY_NEW, "ssh_key")]), &[]).await.expect("digitalocean");
        assert!(report.contains("replaced=1"), "{}", report);
        let calls = calls.lock().unwrap();
        let order: Vec<String> = calls.iter().map(|(m, p, _)| format!("{} {}", m, p.split('?').next().unwrap())).collect();
        assert!(order.iter().position(|c| c == "DELETE /account/keys/9") < order.iter().position(|c| c == "POST /account/keys"), "the old key goes before the new one: {:?}", order);
    }

    #[tokio::test]
    async fn a_value_that_is_not_a_public_key_is_rejected_before_any_request() {
        let (base, calls) = serve(vec![]);
        let config = json!({"base_url": base, "token": "linode-token"});
        let err = linode_sync(&config, &[("DEPLOY".into(), "not a key".into())], &[]).await.unwrap_err();
        assert!(err.contains("not an OpenSSH public key"), "{}", err);
        assert!(calls.lock().unwrap().is_empty());
    }
}
