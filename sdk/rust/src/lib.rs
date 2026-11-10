use reqwest::{Method, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP {status}: {message}")]
    Api { status: u16, message: String, body: Value },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Org { pub id: String, pub name: String, pub role: Option<String> }
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct App { pub id: String, pub org_id: String, pub name: String }
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Env { pub id: String, pub app_id: String, pub name: String }
#[derive(Clone, Deserialize, Serialize)]
pub struct Secret {
    pub id: String,
    pub key: String,
    pub value: String,
    pub path: String,
    #[serde(rename = "type")]
    pub secret_type: String,
    pub comment: String,
    pub tags: String,
    pub version: Option<u64>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Lease {
    pub id: String,
    pub expires_at: i64,
    pub name: Option<String>,
    pub value: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "type")]
    pub lease_type: Option<String>,
}
#[derive(Default, Serialize)]
pub struct LeaseInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub lease_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}
#[derive(Deserialize)]
pub struct Export { pub text: String, pub secrets: Vec<Secret> }
#[derive(Debug, Deserialize)]
pub struct DeployResult { pub deployed: u64, pub sync_errors: Vec<Value> }
#[derive(Deserialize)]
struct SecretList { secrets: Vec<Secret> }

#[derive(Clone)]
pub struct Client {
    base_url: Url,
    token: String,
    http: reqwest::Client,
}

impl Client {
    /// Construction is synchronous; all API methods are async.
    pub fn new(base_url: &str, token: impl Into<String>) -> Result<Self, Error> {
        let base_url = Url::parse(base_url).map_err(|e| Error::InvalidUrl(e.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none()
            || base_url.query().is_some() || base_url.fragment().is_some()
            || !base_url.username().is_empty() || base_url.password().is_some()
        {
            return Err(Error::InvalidUrl("expected HTTP(S) URL without credentials, query, or fragment".into()));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Self { base_url, token: token.into(), http })
    }

    fn url(&self, segments: &[&str]) -> Result<Url, Error> {
        // URL parsers normalize dot segments, so reject them rather than misroute.
        if segments.iter().any(|s| *s == "." || *s == "..") {
            return Err(Error::InvalidUrl("dot path segments are not supported".into()));
        }
        let mut url = self.base_url.clone();
        let mut path = url.path_segments_mut().map_err(|_| Error::InvalidUrl("not a base URL".into()))?;
        path.pop_if_empty().push("api");
        for segment in segments { path.push(segment); }
        drop(path);
        Ok(url)
    }

    async fn request<T: DeserializeOwned>(&self, method: Method, segments: &[&str], body: Option<Value>) -> Result<T, Error> {
        let mut request = self.http.request(method, self.url(segments)?)
            .bearer_auth(&self.token).header("Accept", "application/json");
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text));
            let message = body.get("error").or_else(|| body.get("message"))
                .and_then(Value::as_str).unwrap_or(status.canonical_reason().unwrap_or("API error")).to_string();
            return Err(Error::Api { status: status.as_u16(), message, body });
        }
        Ok(serde_json::from_str(if text.is_empty() { "null" } else { &text })?)
    }

    pub async fn api<T: DeserializeOwned>(&self, method: Method, segments: &[&str], body: Option<Value>, query: &[(String, String)]) -> Result<T, Error> {
        self.management_request(method, segments, body, query, None).await
    }

    pub async fn api_with_step_up<T: DeserializeOwned>(&self, method: Method, segments: &[&str], body: Option<Value>, query: &[(String, String)], step_up: &str) -> Result<T, Error> {
        if step_up.is_empty() || step_up.len() > 512 || !step_up.bytes().all(|b| (32..=126).contains(&b)) {
            return Err(Error::InvalidUrl("invalid step-up grant".into()));
        }
        self.management_request(method, segments, body, query, Some(step_up)).await
    }

    async fn management_request<T: DeserializeOwned>(&self, method: Method, segments: &[&str], body: Option<Value>, query: &[(String, String)], step_up: Option<&str>) -> Result<T, Error> {
        if !matches!(method, Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE | Method::HEAD | Method::OPTIONS) {
            return Err(Error::InvalidUrl("unsupported API method".into()));
        }
        for segment in segments { validate_api_segment(segment).map_err(Error::InvalidUrl)?; }
        let mut url = self.url(segments)?;
        if !query.is_empty() { url.query_pairs_mut().extend_pairs(query.iter().map(|(k,v)| (k,v))); }
        let mut request = self.http.request(method, url).bearer_auth(&self.token).header("Accept", "application/json");
        if let Some(grant) = step_up { request = request.header("X-OpenWarp-Step-Up", grant); }
        if let Some(body) = body { request = request.json(&body); }
        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text));
            let message = body.get("error").or_else(|| body.get("message")).and_then(Value::as_str)
                .unwrap_or(status.canonical_reason().unwrap_or("API error")).to_string();
            return Err(Error::Api { status: status.as_u16(), message, body });
        }
        Ok(serde_json::from_str(if text.is_empty() { "null" } else { &text })?)
    }

    pub async fn me(&self) -> Result<Value, Error> { self.request(Method::GET, &["me"], None).await }
    pub async fn orgs(&self) -> Result<Vec<Org>, Error> { self.request(Method::GET, &["orgs"], None).await }
    pub async fn apps(&self, org: &str) -> Result<Vec<App>, Error> { self.request(Method::GET, &["orgs", org, "apps"], None).await }
    pub async fn envs(&self, app: &str) -> Result<Vec<Env>, Error> { self.request(Method::GET, &["apps", app, "envs"], None).await }
    pub async fn secrets(&self, env: &str) -> Result<Vec<Secret>, Error> {
        Ok(self.request::<SecretList>(Method::GET, &["envs", env, "secrets"], None).await?.secrets)
    }
    pub async fn get_secret(&self, env: &str, key: &str) -> Result<Option<Secret>, Error> {
        let mut matches = self.secrets(env).await?.into_iter().filter(|s| s.key.eq_ignore_ascii_case(key));
        let first = matches.next();
        if matches.next().is_some() {
            return Err(Error::Api { status: 409, message: "Key exists at multiple paths".into(), body: Value::Null });
        }
        Ok(first)
    }
    /// Pass "/", "secret", and "" for the TypeScript defaults.
    pub async fn set_secret(&self, env: &str, key: &str, value: &str, path: &str, secret_type: &str, comment: &str) -> Result<DeployResult, Error> {
        self.request(Method::PUT, &["envs", env, "secrets"], Some(json!({"secrets": [{
            "key": key, "value": value, "path": path, "type": secret_type, "comment": comment, "tags": ""
        }]}))).await
    }
    pub async fn delete_secret(&self, env: &str, key: &str) -> Result<(), Error> {
        if let Some(secret) = self.get_secret(env, key).await? {
            self.request::<Value>(Method::DELETE, &["secrets", &secret.id], None).await?;
        }
        Ok(())
    }
    pub async fn export(&self, env: &str) -> Result<Export, Error> { self.request(Method::GET, &["envs", env, "export"], None).await }
    pub async fn leases(&self, env: &str) -> Result<Vec<Lease>, Error> { self.request(Method::GET, &["envs", env, "dynamic"], None).await }
    pub async fn create_lease(&self, env: &str, input: LeaseInput) -> Result<Lease, Error> {
        self.request(Method::POST, &["envs", env, "dynamic"], Some(serde_json::to_value(input)?)).await
    }
    pub async fn audit(&self, org: &str) -> Result<Vec<Value>, Error> { self.request(Method::GET, &["orgs", org, "audit"], None).await }
}

fn validate_api_segment(segment: &str) -> Result<(), String> {
    let mut decoded = segment.to_string();
    loop {
        if decoded.chars().any(|c| c.is_control()) || decoded.contains('\\') || decoded.contains("://") || decoded.starts_with("//")
            || decoded.split('/').any(|s| s == "." || s == "..") { return Err("unsafe API path segment".into()); }
        if !decoded.contains('%') { return Ok(()); }
        let bytes = decoded.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let pair = bytes.get(i+1..i+3).ok_or("malformed API path encoding")?;
                let hex = std::str::from_utf8(pair).map_err(|_| "malformed API path encoding")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "malformed API path encoding")?);
                i += 3;
            } else { out.push(bytes[i]); i += 1; }
        }
        decoded = String::from_utf8(out).map_err(|_| "invalid API path encoding")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_encoded_urls_with_base_prefix() {
        let client = Client::new("https://example.invalid/prefix/", "token").unwrap();
        assert_eq!(client.url(&["envs", "a/b ?#%雪", "secrets"]).unwrap().as_str(),
            "https://example.invalid/prefix/api/envs/a%2Fb%20%3F%23%25%E9%9B%AA/secrets");
    }

    #[test]
    fn rejects_ambiguous_segments_and_base_urls() {
        let client = Client::new("https://example.invalid", "token").unwrap();
        assert!(client.url(&["envs", ".."]).is_err());
        assert!(Client::new("https://example.invalid?query=yes", "token").is_err());
        assert!(Client::new("file:///tmp", "token").is_err());
    }
}
