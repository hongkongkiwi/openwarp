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
    // Only compiled for the D1 smoke harness, which builds with `d1-smoke`.
    // The production build never enables the feature, so this route is absent.
    #[cfg(feature = "d1-smoke")]
    if req.url()?.path() == "/__internal/migrate-d1" {
        let d1 = env.d1("DB")?;
        return match crate::migrate::apply(&d1, crate::migrate::MIGRATIONS, Default::default()).await {
            Ok(report) => Response::ok(format!("applied={:?} squashed={}", report.applied, report.squashed)),
            Err(error) => Response::error(format!("migration failed: {}", error), 500),
        };
    }
    if req.url()?.path().starts_with("/__internal/") { return Response::error("not found", 404); }
    let too_large = req.headers().get("content-length").ok().flatten().and_then(|v| v.parse::<usize>().ok()).map(|n| n > MAX_BODY).unwrap_or(false);
    if too_large { return Response::error("payload too large", 413); }
    let stub = env.durable_object(DO_BINDING)?.get_by_name(OBJECT_NAME)?;
    stub.fetch_with_request(req).await
}

#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    if let Ok(stub) = env.durable_object(DO_BINDING).and_then(|ns| ns.get_by_name(OBJECT_NAME)) {
        if let Ok(req) = Request::new("https://openwarp.internal/__internal/rotation-tick", Method::Post) {
            let _ = stub.fetch_with_request(req).await;
        }
    }
}

#[durable_object]
pub struct OpenWarp {
    state: State,
    store: Arc<crate::app::AppState>,
    app: axum::Router,
}

impl DurableObject for OpenWarp {
    fn new(state: State, env: Env) -> Self {
        let mut cfg = HashMap::new();
        for key in envcfg::KEYS {
            let value = env.var(key).map(|v| v.to_string()).or_else(|_| env.secret(key).map(|s| s.to_string())).ok();
            if let Some(v) = value { cfg.insert((*key).to_string(), v); }
        }
        envcfg::init(cfg);
        crate::app::validate_region_env().expect("region configuration");
        let master: [u8; 32] = envcfg::var("OPENWARP_MASTER_KEY")
            .map_err(|_| "OPENWARP_MASTER_KEY binding is required on Workers".to_string())
            .and_then(|v| oc::unb64(&v).map_err(|_| "OPENWARP_MASTER_KEY is not valid base64".to_string()))
            .and_then(|b| b.try_into().map_err(|_| "OPENWARP_MASTER_KEY must decode to exactly 32 bytes".to_string()))
            .expect("OPENWARP_MASTER_KEY");
        let db = Db::from_do_sql_now(state.storage()).expect("apply schema");
        let pub_url = envcfg::var("OPENWARP_PUBLIC_URL").unwrap_or_default();
        let store = new_state(db, String::from("durable-object"), oc::random_token("inst"), pub_url, master, crate::LiveSender);
        let app = router(store.clone());
        Self { state, store, app }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if req.url()?.path() == "/__internal/rotation-tick" {
            process_maintenance(&self.store).await;
            self.drain_jobs();
            return Response::ok("ok");
        }
        let request = match to_axum(req).await { Ok(request) => request, Err((message, status)) => return Response::error(message, status) };
        let response = self.app.clone().oneshot(request).await.map_err(|e| Error::RustError(e.to_string()))?;
        self.drain_jobs();
        to_worker(response).await
    }
}

impl OpenWarp {
    fn drain_jobs(&self) {
        for job in take_jobs() {
            let db = self.store.db().clone_handle();
            self.state.wait_until(async move { deliver_job(&db, job).await; });
        }
    }
}

async fn to_axum(mut req: Request) -> std::result::Result<axum::extract::Request, (String, u16)> {
    let method = req.method().to_string();
    let uri = match req.url() { Ok(url) => url.to_string(), Err(e) => return Err((e.to_string(), 400)) };
    let peer = req.headers().get("CF-Connecting-IP").ok().flatten().and_then(|ip| ip.parse::<IpAddr>().ok()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let headers: Vec<(String, String)> = req.headers().into_iter().collect();
    let body = match req.bytes().await { Ok(body) => body, Err(e) => return Err((e.to_string(), 400)) };
    if body.len() > MAX_BODY { return Err(("payload too large".to_string(), 413)); }
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
