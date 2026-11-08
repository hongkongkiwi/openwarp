use crate::encrypted_file::{load_identity, read_bounded, MAX_INPUT};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::io::Read;
use zeroize::Zeroizing;

const INVALID: &str = "invalid reference or secret response";

struct Reference { env: String, path: String, key: String }
fn decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes(); let mut out = Vec::new(); let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() { return Err(INVALID.into()); }
            let hex = |b: u8| (b as char).to_digit(16).ok_or(INVALID);
            out.push((hex(bytes[i + 1])? * 16 + hex(bytes[i + 2])?) as u8); i += 3;
        } else { out.push(bytes[i]); i += 1; }
    }
    String::from_utf8(out).map_err(|_| INVALID.into())
}
fn parse(raw: &str) -> Result<Reference, String> {
    let rest = raw.strip_prefix("ow://").ok_or(INVALID)?;
    if rest.contains('?') || rest.contains('#') { return Err(INVALID.into()); }
    let (env, tail) = rest.split_once('/').ok_or(INVALID)?;
    if env.is_empty() || env.len() > 128 || !env.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') { return Err(INVALID.into()); }
    let parts: Vec<String> = tail.split('/').map(decode).collect::<Result<_, _>>()?;
    if parts.iter().any(|s| s.is_empty() || s == "." || s == ".." || s.contains('/') || s.chars().any(char::is_control)) { return Err(INVALID.into()); }
    let key = parts.last().ok_or(INVALID)?.trim().to_uppercase();
    if key.is_empty() { return Err(INVALID.into()); }
    let path = if parts.len() == 1 { "/".into() } else { format!("/{}/", parts[..parts.len()-1].join("/")) };
    Ok(Reference { env: env.into(), path, key })
}

fn response_json(response: reqwest::blocking::Response) -> Result<Value, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    response.take(24 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| INVALID)?;
    if bytes.len() > 24 * 1024 * 1024 { return Err(INVALID.into()); }
    serde_json::from_slice(&bytes).map_err(|_| INVALID.into())
}

type Secrets = HashMap<(String, String), Option<String>>;
pub(crate) struct Resolver<'a> { client: &'a reqwest::blocking::Client, host: &'a str, token: &'a str, identity: Option<&'a str>, cache: HashMap<String, Secrets> }
impl<'a> Resolver<'a> {
    pub(crate) fn new(client: &'a reqwest::blocking::Client, host: &'a str, token: &'a str, identity: Option<&'a str>) -> Self { Self { client, host, token, identity, cache: HashMap::new() } }
    fn get(&self, url: &str) -> Result<reqwest::blocking::Response, String> { self.client.get(url).bearer_auth(self.token).send().map_err(|_| "secret request failed".into()) }
    fn json(&self, url: &str) -> Result<Value, String> {
        let response = self.get(url)?;
        if !response.status().is_success() { return Err("secret request failed".into()); }
        response_json(response)
    }
    fn fetch(&self, env: &str) -> Result<Secrets, String> {
        let base = format!("{}/api/envs/{}", self.host.trim_end_matches('/'), env);
        let mut offset = 0usize; let mut result = Secrets::new();
        loop {
            let response = self.get(&format!("{}/secrets?limit=500&offset={}", base, offset))?;
            if response.status().as_u16() == 409 && offset == 0 {
                let identity = self.identity.ok_or("client-encrypted environment requires --identity")?;
                let meta = self.json(&format!("{}/e2e/meta", base))?;
                if !matches!(meta["mode"].as_str(), Some("e2e" | "delegated")) { return Err(INVALID.into()); }
                let data = self.json(&format!("{}/e2e/secrets", base))?;
                let kp = load_identity(Path::new(identity))?;
                let raw = Zeroizing::new(kp.decrypt(data["wrapped_key"].as_str().ok_or(INVALID)?).map_err(|_| INVALID)?);
                let key: &[u8;32] = raw.as_slice().try_into().map_err(|_| INVALID)?;
                let rows = data["secrets"].as_array().ok_or(INVALID)?;
                if rows.len() > 10000 { return Err(INVALID.into()); }
                for row in rows {
                    let decrypt = |field: &str| -> Result<String, String> {
                        let bytes = Zeroizing::new(openwarp_crypto::decrypt_symmetric(key, row[field].as_str().ok_or(INVALID)?).map_err(|_| INVALID)?);
                        String::from_utf8(bytes.to_vec()).map_err(|_| INVALID.into())
                    };
                    let name = decrypt("key_enc")?;
                    let value = if row["secret_type"].as_str().or_else(|| row["type"].as_str()) == Some("sealed") { None } else { Some(decrypt("value_enc")?) };
                    let path = match row["path_enc"].as_str() { Some(s) if !s.is_empty() => decrypt("path_enc")?, _ => row["path"].as_str().unwrap_or("/").to_string() };
                    insert(&mut result, &path, &name, value.as_deref())?;
                }
                return Ok(result);
            }
            if !response.status().is_success() { return Err("secret request failed".into()); }
            let data = response_json(response)?;
            let rows = data["secrets"].as_array().ok_or(INVALID)?;
            let total = data["total"].as_u64().ok_or(INVALID)? as usize;
            let limit = data["limit"].as_u64().ok_or(INVALID)? as usize;
            let received_offset = data["offset"].as_u64().ok_or(INVALID)? as usize;
            if total > 10000 || limit == 0 || limit > 1000 || received_offset != offset || rows.len() > limit || offset + rows.len() > total { return Err(INVALID.into()); }
            for row in rows {
                let unavailable = row["type"].as_str().ok_or(INVALID)? == "sealed" || row["decrypt_error"].as_bool().ok_or(INVALID)?;
                let value = if unavailable { None } else { Some(row["value"].as_str().ok_or(INVALID)?) };
                insert(&mut result, row["path"].as_str().ok_or(INVALID)?, row["key"].as_str().ok_or(INVALID)?, value)?;
            }
            offset += rows.len(); if offset == total { return Ok(result); }
            if rows.is_empty() || offset >= 10000 { return Err(INVALID.into()); }
        }
    }
    fn resolve(&mut self, r: &Reference) -> Result<String, String> {
        if !self.cache.contains_key(&r.env) { let secrets = self.fetch(&r.env)?; self.cache.insert(r.env.clone(), secrets); }
        self.cache.get(&r.env).and_then(|s| s.get(&(r.path.clone(), r.key.clone()))).and_then(Clone::clone).ok_or_else(|| "secret reference not found or unreadable".into())
    }
}
fn insert(result: &mut Secrets, path: &str, key: &str, value: Option<&str>) -> Result<(), String> {
    if path.is_empty() || path.len() > 256 || path.chars().any(char::is_control) || key.is_empty() || result.insert((path.into(), key.to_uppercase()), value.map(str::to_string)).is_some() { return Err(INVALID.into()); }
    Ok(())
}
pub(crate) fn inject(resolver: &mut Resolver<'_>, input: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(input, MAX_INPUT)?; let text = std::str::from_utf8(&bytes).map_err(|_| INVALID)?;
    let mut output = String::new(); let mut rest = text;
    while let Some(start) = rest.find("{{ow://") {
        output.push_str(&rest[..start]); let after = &rest[start + 2..];
        let end = after.find("}}").ok_or(INVALID)?; let reference = parse(&after[..end])?;
        output.push_str(&resolver.resolve(&reference)?); rest = &after[end + 2..];
    }
    output.push_str(rest); Ok(output.into_bytes())
}
pub(crate) fn bindings(resolver: &mut Resolver<'_>, file: &Path) -> Result<BTreeMap<String, String>, String> {
    let bytes = read_bounded(file, MAX_INPUT)?;
    let refs: BTreeMap<String, String> = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    let mut values = BTreeMap::new();
    for (name, raw) in refs {
        let mut chars = name.bytes();
        if !matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_') || !chars.all(|c| c.is_ascii_alphanumeric() || c == b'_') { return Err(INVALID.into()); }
        let value = resolver.resolve(&parse(&raw)?)?;
        if value.contains('\0') { return Err(INVALID.into()); }
        values.insert(name, value);
    }
    Ok(values)
}
