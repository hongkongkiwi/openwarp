//! Cloudflare Workers entrypoint.
//!
//! The HTTP application runs inside one SQLite-backed Durable Object, which is
//! what lets the Workers build share main's handlers: the object's SQLite
//! handle is synchronous, so the async storage API can serve it without an
//! async rewrite. Deferred delivery runs under `wait_until` after the response.

use crate::{db::Db, deliver_job, envcfg, new_state, process_maintenance, router, take_jobs};
use axum::http as http;
use openwarp_crypto as oc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt;
use worker::*;

const OBJECT_NAME: &str = "openwarp";
const DO_BINDING: &str = "APP";
const MAX_BODY: usize = 8 * 1024 * 1024;

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.url()?.path().starts_with("/__internal/") { return Response::error("not found", 404); }
    let too_large = req.headers().get("content-length").ok().flatten().and_then(|v| v.parse::<usize>().ok()).map(|n| n > MAX_BODY).unwrap_or(false);
    if too_large { return Response::error("payload too large", 413); }
    let stub = env.durable_object(DO_BINDING)?.get_by_name(OBJECT_NAME)?;
    stub.fetch_with_request(req).await
}

#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let result: Result<()> = async {
        let stub = env.durable_object(DO_BINDING)?.get_by_name(OBJECT_NAME)?;
        let req = Request::new("https://openwarp.internal/__internal/rotation-tick", Method::Post)?;
        let response = stub.fetch_with_request(req).await?;
        let status = response.status_code();
        if !(200..300).contains(&status) { return Err(Error::RustError(format!("maintenance returned HTTP {}", status))); }
        Ok(())
    }.await;
    if let Err(error) = result {
        console_error!("scheduled maintenance failed: {}", error);
        panic!("scheduled maintenance failed: {}", error);
    }
}

#[durable_object]
pub struct OpenWarp {
    state: State,
    store: Arc<crate::app::AppState>,
    app: axum::Router,
    initialized: tokio::sync::OnceCell<()>,
}

impl DurableObject for OpenWarp {
    fn new(state: State, env: Env) -> Self {
        let mut cfg = HashMap::new();
        for key in envcfg::KEYS {
            let value = env.var(key).map(|v| v.to_string()).or_else(|_| env.secret(key).map(|s| s.to_string())).ok();
            if let Some(v) = value { cfg.insert((*key).to_string(), v); }
        }
        envcfg::init(cfg);
        crate::validate_auth_env().expect("invalid sign-in configuration");
        let production = envcfg::var("OPENWARP_ENV").ok().as_deref() == Some("production");
        let pub_url = match envcfg::var("OPENWARP_PUBLIC_URL") {
            Ok(url) => url,
            Err(_) if production => panic!("production requires OPENWARP_PUBLIC_URL"),
            Err(_) => String::new(),
        };
        if production {
            let url = crate::http::Url::parse(&pub_url).expect("production requires OPENWARP_PUBLIC_URL as an https:// origin");
            let authority = pub_url.strip_prefix("https://").unwrap_or("");
            let authority = authority.strip_suffix('/').unwrap_or(authority);
            assert!(!authority.is_empty() && !authority.contains(['@', '/', '\\', '?', '#']) && url.scheme() == "https" && url.host_str().is_some()
                && url.username().is_empty() && url.password().is_none() && url.path() == "/"
                && url.query().is_none() && url.fragment().is_none(), "production requires OPENWARP_PUBLIC_URL as an HTTPS origin without credentials, path, query or fragment");
        }
        let master: [u8; 32] = envcfg::var("OPENWARP_MASTER_KEY").ok().map(|v| {
            oc::unb64(&v).map_err(|_| "OPENWARP_MASTER_KEY is not valid base64".to_string())?
                .try_into().map_err(|_| "OPENWARP_MASTER_KEY must decode to exactly 32 bytes".to_string())
        }).transpose().expect("OPENWARP_MASTER_KEY").unwrap_or([0; 32]);
        let db = Db::from_do_storage_now(state.storage()).expect("apply schema");
        let store = new_state(db, String::from("durable-object"), oc::random_token("inst"), pub_url, master, crate::LiveSender);
        let app = router(store.clone());
        if let Ok(pair) = WebSocketRequestResponsePair::new("ping", "pong") { state.set_websocket_auto_response(&pair); }
        Self { state, store, app, initialized: tokio::sync::OnceCell::new() }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if let Err(error) = self.initialized.get_or_try_init(|| async {
            let kms = crate::kms::Kms::from_env()?;
            let master = crate::load_master(self.store.db(), kms.as_ref()).await?;
            crate::app::initialize_master(&self.store, master);
            crate::install_kms(&self.store, kms);
            Ok::<(), String>(())
        }).await {
            console_error!("master initialization failed: {}", error);
            return Response::error("master initialization failed", 503);
        }
        if req.url()?.path() == "/__internal/rotation-tick" {
            if req.method() != Method::Post { return Response::error("method not allowed", 405); }
            process_maintenance(&self.store).await;
            self.drain_jobs();
            self.fanout_live().await;
            return Response::ok("ok");
        }
        let request = match to_axum(req).await { Ok(request) => request, Err((message, status)) => return Response::error(message, status) };
        let response = self.app.clone().oneshot(request).await.map_err(|e| Error::RustError(e.to_string()))?;
        self.drain_jobs();
        if let Some(admission) = response.extensions().get::<crate::app::LiveAdmission>().cloned() {
            let pair = WebSocketPair::new()?;
            pair.server.serialize_attachment(&admission)?;
            // Accept before replay's first await: concurrent writes now include this socket.
            self.state.accept_web_socket(&pair.server);
            pair.server.send_with_str(serde_json::json!({"type":"hello","instance":self.store.instance_id()}).to_string())?;
            self.send_live(&pair.server).await;
            return Response::from_websocket(pair.client);
        }
        self.fanout_live().await;
        to_worker(response).await
    }

    async fn websocket_message(&self, ws: WebSocket, _message: WebSocketIncomingMessage) -> Result<()> {
        self.send_live(&ws).await;
        Ok(())
    }
    async fn websocket_close(&self, ws: WebSocket, _code: usize, _reason: String, _was_clean: bool) -> Result<()> {
        let _ = ws.close(Some(1000), Some("closed"));
        Ok(())
    }
    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        let _ = ws.close(Some(1011), Some("socket error"));
        Ok(())
    }
}

impl OpenWarp {
    async fn fanout_live(&self) {
        for ws in self.state.get_websockets() { self.send_live(&ws).await; }
    }
    async fn send_live(&self, ws: &WebSocket) {
        let Ok(Some(mut admission)) = ws.deserialize_attachment::<crate::app::LiveAdmission>() else {
            let _ = ws.close(Some(1008), Some("missing admission")); return;
        };
        if self.store.live_identity(&admission).await.is_err() {
            let _ = ws.close(Some(1008), Some("credential revoked or expired")); return;
        }
        loop {
            let events = match self.store.live_replay(admission.cursor).await {
                Ok(events) => events,
                Err(_) => { let _ = ws.close(Some(1011), Some("replay failed")); return; }
            };
            let full = events.len() == 500;
            for event in events {
                let cursor = event.get("id").and_then(serde_json::Value::as_i64).unwrap_or(admission.cursor);
                // A nested fetch may already have delivered this row while authorization awaited.
                if let Ok(Some(current)) = ws.deserialize_attachment::<crate::app::LiveAdmission>() {
                    if current.cursor >= cursor { admission.cursor = current.cursor; continue; }
                }
                let allowed = self.store.live_authorize(&admission, &event).await;
                if let Ok(Some(current)) = ws.deserialize_attachment::<crate::app::LiveAdmission>() {
                    if current.cursor >= cursor { admission.cursor = current.cursor; continue; }
                }
                if allowed && ws.send_with_str(event.to_string()).is_err() { let _ = ws.close(Some(1011), Some("send failed")); return; }
                admission.cursor = cursor;
                if ws.serialize_attachment(&admission).is_err() { let _ = ws.close(Some(1011), Some("cursor failed")); return; }
            }
            if !full { break; }
        }
    }
    fn drain_jobs(&self) {
        for job in take_jobs() {
            let db = self.store.db().clone_handle();
            self.state.wait_until(async move { deliver_job(&db, job).await; });
        }
    }
}

async fn to_axum(req: Request) -> std::result::Result<axum::extract::Request, (String, u16)> {
    use worker::wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    let method = req.method().to_string();
    let uri = match req.url() { Ok(url) => url.to_string(), Err(e) => return Err((e.to_string(), 400)) };
    let peer = req.headers().get("CF-Connecting-IP").ok().flatten().and_then(|ip| ip.parse::<IpAddr>().ok()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let headers: Vec<(String, String)> = req.headers().into_iter().collect();
    let mut body = Vec::new();
    if let Some(stream) = req.inner().body() {
        let reader = stream.get_reader().unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        loop {
            let chunk = match JsFuture::from(reader.read()).await {
                Ok(chunk) => chunk,
                Err(e) => { let _ = JsFuture::from(reader.cancel()).await; reader.release_lock(); return Err((format!("request body read failed: {:?}", e), 400)); }
            };
            if js_sys::Reflect::get(&chunk, &"done".into()).ok().and_then(|v| v.as_bool()).unwrap_or(false) { break; }
            let value = match js_sys::Reflect::get(&chunk, &"value".into()) {
                Ok(value) => value,
                Err(e) => { let _ = JsFuture::from(reader.cancel()).await; reader.release_lock(); return Err((format!("invalid body chunk: {:?}", e), 400)); }
            };
            let bytes = value.unchecked_into::<js_sys::Uint8Array>();
            let length = bytes.length() as usize;
            if length > MAX_BODY - body.len() {
                let _ = JsFuture::from(reader.cancel()).await;
                reader.release_lock();
                return Err(("payload too large".to_string(), 413));
            }
            let start = body.len();
            body.resize(start + length, 0);
            bytes.copy_to(&mut body[start..]);
        }
        reader.release_lock();
    }
    let mut out = match http::Request::builder()
        .method(match method.parse::<http::Method>() { Ok(m) => m, Err(e) => return Err((e.to_string(), 400)) })
        .uri(uri)
        .body(axum::body::Body::from(body)) {
        Ok(request) => request,
        Err(e) => return Err((e.to_string(), 400)),
    };
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (http::header::HeaderName::try_from(name.as_str()), http::header::HeaderValue::try_from(value.as_bytes())) {
            out.headers_mut().append(name, value);
        }
    }
    out.extensions_mut().insert(crate::app::PeerAddr(peer));
    Ok(out)
}

async fn to_worker(res: axum::response::Response) -> Result<Response> {
    let status = res.status().as_u16();
    let headers: Vec<(String, String)> = res.headers().iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string()))).collect();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.map_err(|e| Error::RustError(e.to_string()))?;
    let out = Response::from_bytes(body.to_vec())?.with_status(status);
    for (name, value) in headers { out.headers().set(&name, &value)?; }
    Ok(out)
}
