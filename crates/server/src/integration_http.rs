//! Integration-owned HTTP transport. Keep policy on the request and connector,
//! including token exchanges and clients with custom TLS identities.
use serde::Serialize;
use std::net::IpAddr;

pub(crate) fn restricted() -> bool {
    crate::envcfg::var("OPENWARP_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false)
        && !crate::envcfg::var("OPENWARP_ALLOW_PRIVATE_EGRESS").map(|v| v == "1").unwrap_or(false)
}

pub(crate) fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => ip_allowed(v6.to_ipv4_mapped().unwrap().into()),
        IpAddr::V4(v4) => { let [a,b,c,_]=v4.octets(); !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() || a==0 || a>=240 || (a==100 && (64..=127).contains(&b)) || (a==192 && b==0 && (c==0 || c==2)) || (a==198 && (b==18 || b==19 || (b==51 && c==100))) || (a==203 && b==0 && c==113)) },
        IpAddr::V6(v6) => { let n=v6.segments(); (n[0]&0xe000)==0x2000 && n[0]!=0x2002 && !(n[0]==0x2001 && (n[1]<0x0200 || n[1]==0x0db8)) && !(n[0]==0x3fff && (n[1]&0xf000)==0) },
    }
}

fn validate_url(url: &reqwest::Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        return Err("invalid integration endpoint URL".into());
    }
    Ok(())
}

pub(crate) fn validate_integration_url(raw: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw).map_err(|_| "invalid integration endpoint URL".to_string())?;
    validate_url(&url)
}

fn validate_destination(url: &reqwest::Url, restrict: bool) -> Result<(), String> {
    validate_url(url)?;
    let host = url.host_str().unwrap().trim_start_matches('[').trim_end_matches(']');
    if restrict && (host.trim_end_matches('.').eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| !ip_allowed(ip))) {
        return Err("integration endpoint blocked by egress policy".into());
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_resolved(addrs: &[std::net::SocketAddr], restrict: bool) -> Result<(), std::io::Error> {
    if addrs.is_empty() { return Err(std::io::Error::other("empty DNS response")); }
    if restrict && addrs.iter().any(|addr| !ip_allowed(addr.ip())) { return Err(std::io::Error::other("blocked by egress policy")); }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub(crate) struct Resolver { pub restrict: bool, pub blocked: std::sync::Arc<std::sync::atomic::AtomicBool> }
#[cfg(not(target_arch = "wasm32"))]
impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let restrict = self.restrict; let blocked = self.blocked.clone();
        Box::pin(async move {
            let addrs: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if let Err(error) = validate_resolved(&addrs, restrict) {
                if !addrs.is_empty() { blocked.store(true, std::sync::atomic::Ordering::Relaxed); }
                return Err(error.into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[derive(Clone)]
pub(crate) struct Client { inner: reqwest::Client, restrict: bool }
impl Client {
    pub fn new() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        { Self::from_builder(reqwest::Client::builder()).expect("integration HTTP client unavailable") }
        #[cfg(target_arch = "wasm32")]
        { Self { inner: reqwest::Client::new(), restrict: restricted() } }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_builder(builder: reqwest::ClientBuilder) -> Result<Self, String> {
        let restrict = restricted();
        let inner = builder.no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(30))
            .dns_resolver(std::sync::Arc::new(Resolver { restrict, blocked: Default::default() }))
            .build().map_err(|_| "integration HTTP client unavailable")?;
        Ok(Self { inner, restrict })
    }
    pub fn request(&self, method: reqwest::Method, url: impl AsRef<str>) -> RequestBuilder {
        let raw = url.as_ref();
        let error = reqwest::Url::parse(raw).map_err(|_| "invalid integration endpoint URL".to_string())
            .and_then(|url| validate_destination(&url, self.restrict)).err();
        // Reqwest strips URL userinfo into Basic auth, so reject it before building.
        let inner = self.inner.request(method, if error.is_some() { "" } else { raw }).timeout(std::time::Duration::from_secs(30));
        RequestBuilder { inner, restrict: self.restrict, error }
    }
    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder { self.request(reqwest::Method::GET, url) }
    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder { self.request(reqwest::Method::POST, url) }
    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder { self.request(reqwest::Method::PUT, url) }
    pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder { self.request(reqwest::Method::PATCH, url) }
    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder { self.request(reqwest::Method::DELETE, url) }
}

pub(crate) struct RequestBuilder { inner: reqwest::RequestBuilder, restrict: bool, error: Option<String> }
impl RequestBuilder {
    pub fn header(mut self, name: &str, value: impl ToString) -> Self { self.inner = self.inner.header(name, value.to_string()); self }
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self { self.inner = self.inner.bearer_auth(token.as_ref()); self }
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.inner = self.inner.json(value); self }
    pub fn body(mut self, body: impl Into<reqwest::Body>) -> Self { self.inner = self.inner.body(body); self }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn send(self) -> Result<Response, String> {
        if let Some(error) = self.error { return Err(error); }
        let (client, request) = self.inner.build_split();
        let request = request.map_err(|_| "invalid integration request")?;
        validate_destination(request.url(), self.restrict)?;
        client.execute(request).await.map_err(|_| "integration endpoint unreachable".into())
    }
    #[cfg(target_arch = "wasm32")]
    pub async fn send(self) -> Result<Response, String> {
        crate::http::SendFuture::new(async move {
            use worker::wasm_bindgen::JsValue;
            if let Some(error) = self.error { return Err(error); }
            let request = self.inner.build().map_err(|_| "invalid integration request")?;
            validate_destination(request.url(), self.restrict)?;
            // Fetch cannot pin the connector's DNS answers. Production fails closed
            // even for public hostnames; URL validation alone is not DNS enforcement.
            if self.restrict { return Err("policy-protected integration HTTP requires the native server; Workers cannot verify connector DNS".into()); }
            let timeout = request.timeout().copied().unwrap_or(std::time::Duration::from_secs(30));
            let headers = worker::Headers::new();
            for (name, value) in request.headers() {
                headers.set(name.as_str(), value.to_str().map_err(|_| "invalid integration header")?).map_err(|_| "invalid integration header")?;
            }
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::from(request.method().as_str().to_string())).with_headers(headers).with_redirect(worker::RequestRedirect::Manual);
            if let Some(body) = request.body() {
                let bytes = body.as_bytes().ok_or("unsupported integration request body")?;
                init.with_body(Some(JsValue::from(js_sys::Uint8Array::from(bytes))));
            }
            let request = worker::Request::new_with_init(request.url().as_str(), &init).map_err(|_| "invalid integration request")?;
            let controller = worker::AbortController::default();
            let signal = controller.signal();
            let abort = AbortOnDrop(Some(controller));
            let fetch = worker::Fetch::Request(request);
            let operation = fetch.send_with_signal(&signal);
            let deadline = worker::Delay::from(timeout);
            futures_util::pin_mut!(operation, deadline);
            match futures_util::future::select(deadline, operation).await {
                futures_util::future::Either::Left(_) => Err("integration request timed out".into()),
                futures_util::future::Either::Right((result, _)) => {
                    let inner = result.map_err(|_| "integration endpoint unreachable")?;
                    Ok(Response { inner, _abort: abort, timeout })
                }
            }
        }).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type Response = reqwest::Response;
#[cfg(target_arch = "wasm32")]
struct AbortOnDrop(Option<worker::AbortController>);
#[cfg(target_arch = "wasm32")]
impl Drop for AbortOnDrop { fn drop(&mut self) { if let Some(controller) = self.0.take() { controller.abort(); } } }
#[cfg(target_arch = "wasm32")]
pub(crate) struct Response { inner: worker::Response, _abort: AbortOnDrop, timeout: std::time::Duration }
#[cfg(target_arch = "wasm32")]
unsafe impl Send for Response {}
#[cfg(target_arch = "wasm32")]
impl Response {
    pub fn status(&self) -> reqwest::StatusCode { reqwest::StatusCode::from_u16(self.inner.status_code()).expect("HTTP status") }
    pub async fn text(mut self) -> Result<String, String> {
        crate::http::SendFuture::new(async move {
            let _abort = self._abort;
            let operation = self.inner.text(); let deadline = worker::Delay::from(self.timeout);
            futures_util::pin_mut!(operation, deadline);
            match futures_util::future::select(deadline, operation).await {
                futures_util::future::Either::Left(_) => Err("integration response timed out".into()),
                futures_util::future::Either::Right((result, _)) => result.map_err(|_| "integration response could not be read".into()),
            }
        }).await
    }
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, String> {
        serde_json::from_str(&self.text().await?).map_err(|_| "invalid integration JSON response".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn send_rejects_url_credentials_before_reqwest_normalizes_them() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = Client { inner: reqwest::Client::builder().no_proxy().build().unwrap(), restrict: false };
        for authority in ["user:password", "user", ":password"] {
            let response = client.post(format!("http://{authority}@{address}/sync")).bearer_auth("dummy").json(&serde_json::json!({"secret":"dummy"})).send().await;
            assert!(matches!(response, Err(error) if error == "invalid integration endpoint URL"));
        }
        assert!(client.get("not a URL").header("x-test", "dummy").send().await.is_err());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await.is_err());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096]; assert!(socket.read(&mut buffer).await.unwrap() > 0);
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        assert!(client.get(format!("http://{address}/control")).send().await.unwrap().status().is_success());
        server.await.unwrap();
    }
    #[test]
    fn ipv4_special_prefixes_do_not_block_adjacent_public_addresses() {
        for raw in ["192.0.0.0", "192.0.0.255", "192.0.2.0", "192.0.2.255", "198.18.0.0", "198.19.255.255", "198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255"] {
            assert!(!ip_allowed(raw.parse().unwrap()), "special prefix allowed {raw}");
        }
        for raw in ["192.0.1.1", "192.0.3.1", "192.2.0.1", "198.17.255.255", "198.20.0.0", "198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0"] {
            assert!(ip_allowed(raw.parse().unwrap()), "adjacent public address blocked {raw}");
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn connector_policy_rejects_entire_mixed_dns_set() {
        let public: Vec<std::net::SocketAddr> = vec!["8.8.8.8:0".parse().unwrap(), "[2606:4700:4700::1111]:0".parse().unwrap()];
        assert!(validate_resolved(&public, true).is_ok());
        for private in ["127.0.0.1:0", "10.0.0.1:0", "[::1]:0", "[::ffff:127.0.0.1]:0"] {
            let mut mixed = public.clone(); mixed.push(private.parse().unwrap());
            assert!(validate_resolved(&mixed, true).is_err(), "{private}");
            mixed.reverse();
            assert!(validate_resolved(&mixed, true).is_err(), "order must not permit {private}");
            assert!(validate_resolved(&mixed, false).is_ok(), "development/override must permit {private}");
        }
        assert!(validate_resolved(&[], true).is_err());
        assert!(validate_resolved(&[], false).is_err());
    }
    #[test]
    fn destination_policy_checks_literals_and_localhost() {
        for url in ["http://127.0.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://localhost/", "http://localhost./", "http://169.254.169.254/"] {
            let url = reqwest::Url::parse(url).unwrap();
            assert!(validate_destination(&url, true).is_err(), "{url}");
            assert!(validate_destination(&url, false).is_ok(), "{url}");
        }
        assert!(validate_destination(&reqwest::Url::parse("https://8.8.8.8/").unwrap(), true).is_ok());
        assert!(validate_destination(&reqwest::Url::parse("https://api.example.com/").unwrap(), true).is_ok());
        for url in ["ftp://8.8.8.8/", "https://user:password@8.8.8.8/"] {
            assert!(validate_destination(&reqwest::Url::parse(url).unwrap(), false).is_err());
        }
    }
}
