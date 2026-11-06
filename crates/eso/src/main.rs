//! ESO webhook bridge: exposes an OpenWarp environment as the JSON map shape
//! External Secrets Operator expects from a `webhook` SecretStore.
//!
//! The bridge holds no credentials of its own. Callers pass an OpenWarp service
//! token as a Bearer token and every request is authorised by OpenWarp, so the
//! bridge can never return more than that token already allows.

use axum::{extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, routing::get, Json, Router};
use serde_json::{json, Value};
use std::{collections::HashMap, time::Duration};

#[derive(Clone)]
struct Config { upstream: String, client: reqwest::Client }

type ApiError = (StatusCode, Json<Value>);

fn fail(status: StatusCode, message: &str) -> ApiError { (status, Json(json!({"error": message}))) }

fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let raw = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let (scheme, token) = raw.split_once(' ').unwrap_or(("", ""));
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err(fail(StatusCode::UNAUTHORIZED, "send an OpenWarp service token as a Bearer token"));
    }
    Ok(token.trim().to_string())
}

// A reference is an environment id, APP/ENV, or WORKSPACE/APP/ENV. Names are
// resolved through the API so callers never have to copy opaque ids into git.
#[derive(Debug, PartialEq)]
enum Target { EnvId(String), Names { workspace: Option<String>, app: String, env: String } }

fn parse_ref(raw: &str) -> Result<Target, String> {
    let parts: Vec<&str> = raw.split('/').map(str::trim).filter(|p| !p.is_empty()).collect();
    match parts.len() {
        1 => Ok(Target::EnvId(parts[0].to_string())),
        2 => Ok(Target::Names { workspace: None, app: parts[0].to_string(), env: parts[1].to_string() }),
        3 => Ok(Target::Names { workspace: Some(parts[0].to_string()), app: parts[1].to_string(), env: parts[2].to_string() }),
        0 => Err("reference is empty".into()),
        _ => Err("reference must be ENV_ID, APP/ENV or WORKSPACE/APP/ENV".into()),
    }
}

async fn upstream_status(status: StatusCode, response: reqwest::Response) -> ApiError {
    let body = response.text().await.unwrap_or_default();
    let message = serde_json::from_str::<Value>(&body).ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| format!("OpenWarp returned {}", status.as_u16()));
    // 404 must survive so ESO applies its deletionPolicy; server faults become 502.
    let status = if status.is_server_error() { StatusCode::BAD_GATEWAY } else { status };
    fail(status, &message)
}

async fn get_json(cfg: &Config, token: &str, path: &str) -> Result<Value, ApiError> {
    let response = cfg.client.get(format!("{}{}", cfg.upstream, path)).bearer_auth(token).send().await
        .map_err(|e| fail(StatusCode::BAD_GATEWAY, &format!("cannot reach OpenWarp: {e}")))?;
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if !status.is_success() { return Err(upstream_status(status, response).await); }
    response.json::<Value>().await.map_err(|_| fail(StatusCode::BAD_GATEWAY, "OpenWarp returned a non-JSON response"))
}

async fn resolve(cfg: &Config, token: &str, target: &Target) -> Result<String, ApiError> {
    let (workspace, app, env) = match target {
        Target::EnvId(id) => return Ok(id.clone()),
        Target::Names { workspace, app, env } => (workspace, app, env) };
    let orgs = get_json(cfg, token, "/api/orgs").await?;
    let mut matches = Vec::new();
    for org in orgs.as_array().cloned().unwrap_or_default() {
        if let Some(wanted) = workspace {
            if org["name"].as_str() != Some(wanted.as_str()) { continue; }
        }
        let Some(org_id) = org["id"].as_str().filter(|s| !s.is_empty()) else { continue };
        let apps = get_json(cfg, token, &format!("/api/orgs/{org_id}/apps")).await?;
        for candidate in apps.as_array().cloned().unwrap_or_default() {
            if candidate["name"].as_str() != Some(app.as_str()) { continue; }
            let Some(app_id) = candidate["id"].as_str().filter(|s| !s.is_empty()) else { continue };
            let envs = get_json(cfg, token, &format!("/api/apps/{app_id}/envs")).await?;
            for found in envs.as_array().cloned().unwrap_or_default() {
                if found["name"].as_str() == Some(env.as_str()) {
                    if let Some(id) = found["id"].as_str() { matches.push(id.to_string()); }
                }
            }
        }
    }
    match matches.len() {
        0 => Err(fail(StatusCode::NOT_FOUND, "no environment matches that reference")),
        1 => Ok(matches.remove(0)),
        _ => Err(fail(StatusCode::CONFLICT, "reference matches several environments; prefix it with the workspace name")),
    }
}

fn name_list(keys: &[String]) -> String {
    const SHOWN: usize = 8;
    if keys.len() > SHOWN { format!("{}, and {} more", keys[..SHOWN].join(", "), keys.len() - SHOWN) } else { keys.join(", ") }
}

async fn materialise(cfg: &Config, token: &str, env_id: &str) -> Result<serde_json::Map<String, Value>, ApiError> {
    // base=1 keeps the token owner's personal overrides out of a Deployment.
    let body = get_json(cfg, token, &format!("/api/envs/{env_id}/export?base=1")).await?;
    let mut data = serde_json::Map::new();
    let (mut broken, mut sealed) = (Vec::new(), Vec::new());
    for item in body["secrets"].as_array().cloned().unwrap_or_default() {
        let key = item["key"].as_str().unwrap_or("");
        if key.is_empty() { continue; }
        if item["decrypt_error"].as_bool().unwrap_or(false) { broken.push(key.to_string()); continue; }
        match item["value"].as_str() {
            Some(value) => { data.insert(key.to_string(), json!(value)); }
            None => sealed.push(key.to_string()) }
    }
    // Never hand ESO an empty string where the real value is unavailable: an
    // application would start with a silently wrong credential.
    if !broken.is_empty() || !sealed.is_empty() {
        let mut reasons = Vec::new();
        if !broken.is_empty() { reasons.push(format!("{} secrets cannot be decrypted on the server ({})", broken.len(), name_list(&broken))); }
        if !sealed.is_empty() { reasons.push(format!("{} sealed secrets have no server-side value ({})", sealed.len(), name_list(&sealed))); }
        return Err((StatusCode::UNPROCESSABLE_ENTITY, Json(json!({
            "error": format!("environment cannot be materialised: {}", reasons.join("; ")),
            "code": "unmaterialisable_environment" }))));
    }
    Ok(data)
}

async fn export(cfg: Config, headers: HeaderMap, raw: String) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let raw = raw.trim();
    if raw.is_empty() { return Err(fail(StatusCode::BAD_REQUEST, "send ref=ENV_ID, APP/ENV or WORKSPACE/APP/ENV")); }
    let target = parse_ref(raw).map_err(|e| fail(StatusCode::BAD_REQUEST, &e))?;
    let env_id = resolve(&cfg, &token, &target).await?;
    let data = materialise(&cfg, &token, &env_id).await?;
    Ok(Json(json!({"data": data})))
}

async fn export_query(State(cfg): State<Config>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    export(cfg, headers, q.get("ref").cloned().unwrap_or_default()).await }
async fn export_body(State(cfg): State<Config>, headers: HeaderMap, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    export(cfg, headers, body.get("ref").and_then(Value::as_str).unwrap_or("").to_string()).await }
async fn export_path(State(cfg): State<Config>, headers: HeaderMap, Path(reference): Path<String>) -> Result<Json<Value>, ApiError> {
    export(cfg, headers, reference).await }

fn router(cfg: Config) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/export", get(export_query).post(export_body))
        .route("/v1/export/{*reference}", get(export_path))
        .with_state(cfg)
}

#[tokio::main]
async fn main() {
    let upstream = std::env::var("OPENWARP_URL").unwrap_or_default().trim_end_matches('/').to_string();
    if upstream.is_empty() {
        eprintln!("OPENWARP_URL is required, for example http://openwarp:8080");
        std::process::exit(2);
    }
    let addr = std::env::var("OPENWARP_ESO_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".into());
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().expect("http client");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind OPENWARP_ESO_ADDR");
    eprintln!("openwarp-eso listening on {addr}, upstream {upstream}");
    axum::serve(listener, router(Config { upstream, client })).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json as v;

    fn config(upstream: &str) -> Config {
        Config { upstream: upstream.to_string(), client: reqwest::Client::new() } }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    // Stands in for OpenWarp: one env id, one name path, and a 404 for anything else.
    async fn stub_upstream() -> String {
        serve(Router::new()
            .route("/api/orgs", get(|| async { Json(v!([{"id": "o1", "name": "Acme"}])) }))
            .route("/api/orgs/{oid}/apps", get(|| async { Json(v!([{"id": "a1", "name": "api"}])) }))
            .route("/api/apps/{aid}/envs", get(|| async { Json(v!([
                {"id": "e1", "name": "Production"}, {"id": "e2", "name": "Staging"}])) }))
            .route("/api/envs/{eid}/export", get(|headers: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                if bearer(&headers).is_err() { return (StatusCode::UNAUTHORIZED, Json(v!({"error": "missing Bearer token"}))) }
                if q.get("base").map(String::as_str) != Some("1") {
                    return (StatusCode::BAD_REQUEST, Json(v!({"error": "the bridge must request canonical values"}))) }
                (StatusCode::OK, Json(v!({"text": "", "secrets": [
                    {"key": "DATABASE_URL", "value": "postgres://db", "decrypt_error": false},
                    {"key": "API_KEY", "value": "test-value", "decrypt_error": false}]})))
            }))).await
    }

    #[test]
    fn references_parse_into_ids_and_names() {
        assert_eq!(parse_ref("abc123"), Ok(Target::EnvId("abc123".into())));
        assert_eq!(parse_ref("api/Production"), Ok(Target::Names { workspace: None, app: "api".into(), env: "Production".into() }));
        assert_eq!(parse_ref("Acme/api/Production"), Ok(Target::Names { workspace: Some("Acme".into()), app: "api".into(), env: "Production".into() }));
        assert!(parse_ref("a/b/c/d").is_err());
        assert!(parse_ref("  ").is_err());
    }

    #[tokio::test]
    async fn exports_named_environment_as_eso_map() {
        let upstream = stub_upstream().await;
        let bridge = serve(router(config(&upstream))).await;
        let body: Value = reqwest::Client::new().get(format!("{bridge}/v1/export?ref=Acme/api/Production"))
            .bearer_auth("service-token").send().await.unwrap().json().await.unwrap();
        assert_eq!(body, v!({"data": {"DATABASE_URL": "postgres://db", "API_KEY": "test-value"}}));
    }

    #[tokio::test]
    async fn accepts_two_segment_reference_and_path_form() {
        let upstream = stub_upstream().await;
        let bridge = serve(router(config(&upstream))).await;
        let client = reqwest::Client::new();
        let query = client.get(format!("{bridge}/v1/export?ref=api/Staging")).bearer_auth("t").send().await.unwrap();
        assert_eq!(query.status(), StatusCode::OK);
        let path = client.get(format!("{bridge}/v1/export/e1")).bearer_auth("t").send().await.unwrap();
        assert_eq!(path.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_missing_token_without_calling_upstream() {
        let bridge = serve(router(config("http://127.0.0.1:1"))).await;
        let response = reqwest::get(format!("{bridge}/v1/export?ref=e1")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_reference_stays_404_for_deletion_policy() {
        let upstream = stub_upstream().await;
        let bridge = serve(router(config(&upstream))).await;
        let response = reqwest::Client::new().get(format!("{bridge}/v1/export?ref=Acme/api/Development"))
            .bearer_auth("t").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unmaterialisable_environment_is_refused() {
        let upstream = serve(Router::new().route("/api/envs/{eid}/export", get(|| async {
            Json(v!({"secrets": [
                {"key": "PRIVATE_KEY", "value": null, "decrypt_error": false},
                {"key": "OK", "value": "fine", "decrypt_error": false}]}))
        }))).await;
        let bridge = serve(router(config(&upstream))).await;
        let response = reqwest::Client::new().get(format!("{bridge}/v1/export?ref=e1"))
            .bearer_auth("t").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "unmaterialisable_environment");
        assert!(body["error"].as_str().unwrap().contains("PRIVATE_KEY"));
        assert!(!body["error"].as_str().unwrap().contains("fine"));
    }

    #[tokio::test]
    async fn upstream_server_fault_is_reported_as_bad_gateway() {
        let upstream = serve(Router::new().route("/api/envs/{eid}/export", get(|| async {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(v!({"error": "database is down"}))) }))).await;
        let bridge = serve(router(config(&upstream))).await;
        let response = reqwest::Client::new().get(format!("{bridge}/v1/export?ref=e1"))
            .bearer_auth("t").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
