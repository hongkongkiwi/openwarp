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
pub async fn provider_post_bounded(request: RequestBuilder, limit: usize) -> Result<Vec<u8>, String> {
    let response = request.send().await.map_err(|_| "provider request failed")?;
    if !response.status().is_success() { return Err("provider request failed".into()); }
    read_bounded(response, limit).await
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
        pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder::new(self.0.get(url.as_ref())) }
        pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder::new(self.0.post(url.as_ref())) }
        pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder::new(self.0.put(url.as_ref())) }
        pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder::new(self.0.patch(url.as_ref())) }
        pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder::new(self.0.delete(url.as_ref())) }
        pub fn request(&self, method: reqwest::Method, url: impl AsRef<str>) -> RequestBuilder { RequestBuilder::new(self.0.request(method, url.as_ref())) }
    }

    pub async fn provider_post_bounded(request: RequestBuilder, limit: usize) -> Result<Vec<u8>, String> {
        SendFuture::new(async move {
            use futures_util::StreamExt;
            use worker::wasm_bindgen::JsValue;
            let request = request.0.build().map_err(|_| "provider request failed")?;
            let headers = worker::Headers::new();
            for (name, value) in request.headers() {
                headers.set(name.as_str(), value.to_str().map_err(|_| "provider request failed")?).map_err(|_| "provider request failed")?;
            }
            let body = request.body().and_then(|body| body.as_bytes()).ok_or("provider request failed")?;
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Post).with_headers(headers)
                .with_redirect(worker::RequestRedirect::Error)
                .with_body(Some(JsValue::from(js_sys::Uint8Array::from(body))));
            let request = worker::Request::new_with_init(request.url().as_str(), &init).map_err(|_| "provider request failed")?;
            let mut response = worker::Fetch::Request(request).send().await.map_err(|_| "provider request failed")?;
            if !(200..300).contains(&response.status_code()) { return Err("provider request failed".into()); }
            let mut stream = response.stream().map_err(|_| "provider response could not be read")?;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| "provider response could not be read")?;
                if chunk.len() > limit - bytes.len() { return Err("provider response is too large".into()); }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        }).await
    }

    pub struct RequestBuilder(reqwest::RequestBuilder);

    impl RequestBuilder {
        fn new(request: reqwest::RequestBuilder) -> Self { Self(request.timeout(std::time::Duration::from_secs(30))) }
        pub fn header(mut self, name: &str, value: impl ToString) -> Self { self.0 = self.0.header(name, value.to_string()); self }
        pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self { self.0 = self.0.bearer_auth(token.as_ref()); self }
        pub fn basic_auth(mut self, user: &str, password: Option<&str>) -> Self { self.0 = self.0.basic_auth(user, password); self }
        pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.0 = self.0.json(value); self }
        pub fn form<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.0 = self.0.form(value); self }
        pub fn body(mut self, body: impl Into<reqwest::Body>) -> Self { self.0 = self.0.body(body); self }
        pub fn query<T: Serialize + ?Sized>(mut self, value: &T) -> Self { self.0 = self.0.query(value); self }
        /// Reqwest's wasm AbortController spans fetch and response body reads;
        /// dropping its response or request future aborts and clears the timer.
        pub fn timeout(mut self, timeout: std::time::Duration) -> Self { self.0 = self.0.timeout(timeout); self }
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
    #[tokio::test]
    async fn provider_posts_do_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        for status in [307, 308] {
            let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = destination.local_addr().unwrap();
            let url = format!("http://{}/token", source.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = source.accept().await.unwrap();
                let mut buf = [0; 4096];
                assert!(socket.read(&mut buf).await.unwrap() > 0);
                socket.write_all(format!("HTTP/1.1 {status} Redirect\r\nLocation: http://{target}/stolen\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
            });
            let request = crate::app::http_client().post(&url).form(&[("client_secret", "dummy"), ("code", "dummy")]);
            assert!(super::provider_post_bounded(request, 1024 * 1024).await.is_err());
            server.await.unwrap();
            assert!(tokio::time::timeout(std::time::Duration::from_millis(100), destination.accept()).await.is_err());
        }
    }

    #[test]
    fn base64_cookie_values_survive_header_conversion() {
        let cookie = "ow_session=ow_ab+/cd==; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800; Secure";
        let value = axum::http::HeaderValue::try_from(cookie).expect("cookie value must be a valid header value");
        assert_eq!(value.to_str().expect("visible ASCII"), cookie);
    }
}
