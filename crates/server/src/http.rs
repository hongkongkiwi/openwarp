//! Outbound HTTP with one call surface for both runtimes.
//!
//! Native builds use reqwest directly. On wasm every request is a JS promise,
//! and those futures are not `Send`; axum requires handler futures to be
//! `Send`. The wasm facade therefore wraps them in `SendWrapper`, which asserts
//! single-threaded use at runtime. A Worker isolate has exactly one thread, so
//! the assertion always holds.

pub use inner::*;

#[cfg(not(target_arch = "wasm32"))]
pub async fn read_bounded(mut response: Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "provider response could not be read")? {
        if chunk.len() > limit - bytes.len() { return Err("provider response is too large".into()); }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(target_arch = "wasm32")]
pub async fn read_bounded(response: Response, limit: usize) -> Result<Vec<u8>, String> {
    response.bounded_bytes(limit).await
}

#[cfg(not(target_arch = "wasm32"))]
mod inner {
    pub use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
}

#[cfg(target_arch = "wasm32")]
mod inner {
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    pub use reqwest::{StatusCode, Url};

    /// Unsafe `Send` for a future that must stay on one thread. A Worker
    /// isolate is single-threaded, so this cannot be observed.
    pub struct SendFuture<F>(F);
    impl<F> SendFuture<F> { fn new(f: F) -> Self { Self(f) } }
    unsafe impl<F> Send for SendFuture<F> {}
    impl<F: std::future::Future> std::future::Future for SendFuture<F> {
        type Output = F::Output;
        fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
            unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
        }
    }

    #[derive(Clone)]
    pub struct Client(reqwest::Client);

    impl Default for Client { fn default() -> Self { Self::new() } }

    impl Client {
        pub fn new() -> Self { Self(reqwest::Client::new()) }
        pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder(self.0.get(url.as_ref())) }
        pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder(self.0.post(url.as_ref())) }
        pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder(self.0.put(url.as_ref())) }
        pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder(self.0.patch(url.as_ref())) }
        pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder(self.0.delete(url.as_ref())) }
        pub fn request(&self, method: reqwest::Method, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder(self.0.request(method, url.as_ref())) }
    }

    pub struct RequestBuilder(reqwest::RequestBuilder);

    impl RequestBuilder {
        pub fn header(mut self, name: &str, value: impl AsRef<str>) -> Self { self.0 = self.0.header(name, value.as_ref()); self }
        pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self { self.0 = self.0.bearer_auth(token.as_ref()); self }
        pub fn basic_auth(mut self, user: &str, password: Option<&str>) -> Self { self.0 = self.0.basic_auth(user, password); self }
        pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.0 = self.0.json(value); self }
        pub fn form<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.0 = self.0.form(value); self }
        pub fn body(mut self, body: impl Into<reqwest::Body>) -> Self { self.0 = self.0.body(body); self }
        pub fn query<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.0 = self.0.query(value); self }
        /// The Workers fetch client has no per-request timeout; the platform
        /// enforces request duration, so the native deadline is dropped here.
        pub fn timeout(self, _timeout: std::time::Duration) -> Self { self }
        pub async fn send(self) -> Result<Response, String> {
            SendFuture::new(async move { self.0.send().await.map_err(|e| e.to_string()).map(Response::new) }).await
        }
    }

    pub struct Response(reqwest::Response);
    unsafe impl Send for Response {}

    impl Response {
        fn new(r: reqwest::Response) -> Self { Self(r) }
        pub fn status(&self) -> StatusCode { self.0.status() }
        pub async fn json<T: DeserializeOwned>(self) -> Result<T, String> {
            SendFuture::new(async move { self.0.json::<T>().await.map_err(|e| e.to_string()) }).await
        }
        pub async fn text(self) -> Result<String, String> {
            SendFuture::new(async move { self.0.text().await.map_err(|e| e.to_string()) }).await
        }
        pub async fn bytes(self) -> Result<Vec<u8>, String> {
            SendFuture::new(async move { self.0.bytes().await.map(|b| b.to_vec()).map_err(|e| e.to_string()) }).await
        }
        pub async fn bounded_bytes(self, limit: usize) -> Result<Vec<u8>, String> {
            SendFuture::new(async move {
                use futures_util::StreamExt;
                let stream = self.0.bytes_stream();
                futures_util::pin_mut!(stream);
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|_| "provider response could not be read")?;
                    if chunk.len() > limit - bytes.len() { return Err("provider response is too large".into()); }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(bytes)
            }).await
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    // The Worker entrypoint copies header values through `HeaderValue`, which
    // rejects control bytes only. Base64 session tokens contain `=` and `+`,
    // so this guards against a filter that would drop the session cookie.
    #[test]
    fn base64_cookie_values_survive_header_conversion() {
        let cookie = "ow_session=ow_ab+/cd==; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800; Secure";
        let value = axum::http::HeaderValue::try_from(cookie).expect("cookie value must be a valid header value");
        assert_eq!(value.to_str().expect("visible ASCII"), cookie);
    }
}
