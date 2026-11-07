use axum::{body::{to_bytes, Body}, http::Request, Router};
use hmac::Mac;
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, S};
use serde_json::{json, Value};
use std::{path::PathBuf, process::{Child, Command, Stdio}, sync::atomic::{AtomicU32, Ordering}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tower::ServiceExt;

fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }
fn url64(bytes: &[u8]) -> String { oc::b64(bytes).trim_end_matches('=').replace('+', "-").replace('/', "_") }
struct Reply { status: u16, body: Value }
impl Reply {
    fn ok(self) -> Value { assert_eq!(self.status, 200, "HTTP {}: {}", self.status, self.body); self.body }
    fn denied(&self) -> bool { matches!(self.status, 401 | 403) }
}
struct Fixture { state: S, app: Router }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.unwrap();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','org',?)", &[json!(now())]).await.unwrap();
        for (uid, role) in [("owner", "owner"), ("dev", "developer")] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,'unused','unused','unused',?,1)", &[json!(uid), json!(format!("{}@test.invalid", uid)), json!(now())]).await.unwrap();
            db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org',?,?)", &[json!(uid), json!(role)]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(uid)), json!(uid), json!(now())]).await.unwrap();
        }
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await.unwrap();
        db.exec("INSERT INTO identities(id,org_id,name,role,created_at) VALUES('machine','org','machine','developer',?)", &[json!(now())]).await.unwrap();
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','app',?)", &[json!(now())]).await.unwrap();
        for eid in ["env-a", "env-b"] {
            db.exec("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,'app',?,?,'sse',?)", &[json!(eid), json!(eid), json!(oc::encrypt_symmetric(&[7;32], &[8;32])), json!(now())]).await.unwrap();
        }
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "tests".into(), "https://openwarp.test".into(), [7;32], live, #[cfg(feature = "redis-cache")] None);
        let app = router(state.clone());
        Self { state, app }
    }
    async fn call(&self, method: &str, path: &str, credential: &str, body: Option<Value>) -> Reply {
        let mut req = Request::builder().method(method).uri(path).extension(openwarp_server::PeerAddr(std::net::IpAddr::from([127,0,0,1])));
        if let Some(token) = credential.strip_prefix("cookie:") { req = req.header("cookie", format!("ow_session={}", token)); }
        else if !credential.is_empty() { req = req.header("authorization", format!("Bearer {}", credential)); }
        let body = if let Some(body) = body { req = req.header("content-type", "application/json"); Body::from(body.to_string()) } else { Body::empty() };
        let response = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
        Reply { status, body }
    }
}

#[tokio::test]
async fn cookie_credentials_cannot_escape_bearer_scope_or_mint_permanent_machine_tokens() {
    let f = Fixture::new().await;
    f.state.db().exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,scopes,created_at,created_by) VALUES('scoped','org','app','env-a','scoped',?,'secrets:read',?,'owner')", &[json!(oc::hash_token("scoped")), json!(now())]).await.unwrap();
    f.state.db().exec("INSERT INTO tokens(id,org_id,name,token_hash,kind,created_at,expires_at,created_by) VALUES('machine-token','org','machine',?,'machine',?,?,'machine')", &[json!(oc::hash_token("machine-token")), json!(now()), json!(now()+3600)]).await.unwrap();
    f.call("GET", "/api/envs/env-a/secrets", "scoped", None).await.ok();
    f.call("GET", "/api/envs/env-b/secrets", "cookie:dev", None).await.ok();
    f.call("PUT", "/api/envs/env-b/secrets", "cookie:dev", Some(json!({"secrets":[{"key":"SESSION","value":"allowed"}]}))).await.ok();
    f.call("POST", "/api/apps/app/tokens", "cookie:dev", Some(json!({"name":"session-positive-control","scopes":"secrets:read"}))).await.ok();
    let mut violations = Vec::new();
    let write = json!({"secrets":[{"key":"ESCAPE","value":"denied"}]});
    for (method, path, body) in [
        ("PUT", "/api/envs/env-b/secrets", Some(write.clone())),
        ("GET", "/api/orgs/org/transit/keys", None),
    ] {
        let bearer = f.call(method, path, "scoped", body.clone()).await;
        assert!(bearer.denied(), "bearer negative control {}: {} {}", path, bearer.status, bearer.body);
        let cookie = f.call(method, path, "cookie:scoped", body).await;
        if !cookie.denied() { violations.push(format!("cookie {} {} returned {} {}", method, path, cookie.status, cookie.body)); }
    }
    let mcp = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_secret","arguments":{"env_id":"env-b","key":"MCP_ESCAPE","value":"denied"}}});
    let mut allowed_mcp = mcp.clone(); allowed_mcp["params"]["arguments"]["key"] = json!("MCP_SESSION");
    let session_mcp = f.call("POST", "/mcp", "cookie:dev", Some(allowed_mcp)).await.ok();
    assert!(session_mcp.get("error").is_none() && session_mcp["result"]["isError"] != true, "session MCP positive control: {}", session_mcp);
    let bearer = f.call("POST", "/mcp", "scoped", Some(mcp.clone())).await;
    assert!(bearer.denied() || bearer.body.get("error").is_some() || bearer.body["result"]["isError"] == true, "MCP bearer negative control: {}", bearer.body);
    let cookie = f.call("POST", "/mcp", "cookie:scoped", Some(mcp)).await;
    if !(cookie.denied() || cookie.body.get("error").is_some() || cookie.body["result"]["isError"] == true) { violations.push(format!("MCP cookie write accepted: {}", cookie.body)); }
    let before = f.state.db().query("SELECT id FROM tokens", &[]).await.unwrap().len();
    let mint = json!({"name":"machine-escape","scopes":"*"});
    let bearer = f.call("POST", "/api/apps/app/tokens", "machine-token", Some(mint.clone())).await;
    assert!(bearer.denied(), "machine bearer negative control: {} {}", bearer.status, bearer.body);
    let cookie = f.call("POST", "/api/apps/app/tokens", "cookie:machine-token", Some(mint)).await;
    if !cookie.denied() { violations.push(format!("machine cookie minted permanent credential: {} {}", cookie.status, cookie.body)); }
    let after = f.state.db().query("SELECT id FROM tokens", &[]).await.unwrap().len();
    if after != before { violations.push(format!("machine cookie changed token count {} -> {}", before, after)); }
    let secrets = f.call("GET", "/api/envs/env-b/secrets", "owner", None).await.ok();
    if secrets.to_string().contains("ESCAPE") { violations.push("forbidden cookie writes persisted in env-b".into()); }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[tokio::test]
async fn transit_rewrap_requires_encrypt_and_decrypt_scopes_for_service_and_oauth_tokens() {
    let f = Fixture::new().await;
    let key = f.call("POST", "/api/orgs/org/transit/keys", "owner", Some(json!({"name":"scope-controls"}))).await.ok();
    let base = format!("/api/orgs/org/transit/keys/{}", key["id"].as_str().unwrap());
    let plain = json!({"plaintext":oc::b64(b"local transit control"),"context":"regression"});
    let encrypted = f.call("POST", &format!("{}/encrypt", base), "owner", Some(plain.clone())).await.ok();
    f.call("POST", &format!("{}/rotate", base), "owner", Some(json!({}))).await.ok();
    let input = json!({"ciphertext":encrypted["ciphertext"],"context":"regression"});
    let mut violations = Vec::new();
    for kind in ["service", "oauth"] {
        for (suffix, scope) in [("decrypt", "transit:decrypt"), ("both", "transit:decrypt transit:encrypt")] {
            let token = format!("{}-{}", kind, suffix);
            if kind == "service" {
                f.state.db().exec("INSERT INTO tokens(id,org_id,name,token_hash,scopes,created_at,created_by) VALUES(?,'org',?,?,?,?,'owner')", &[json!(&token), json!(&token), json!(oc::hash_token(&token)), json!(scope), json!(now())]).await.unwrap();
            } else {
                f.state.db().exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,expires_at,created_at) VALUES(?,'local-test','owner',?,?,?)", &[json!(oc::hash_token(&token)), json!(scope), json!(now()+300), json!(now())]).await.unwrap();
            }
        }
        let decrypt_only = format!("{}-decrypt", kind);
        let both = format!("{}-both", kind);
        let forbidden = f.call("POST", &format!("{}/encrypt", base), &decrypt_only, Some(plain.clone())).await;
        assert_eq!(forbidden.status, 403, "{} encrypt negative control: {}", kind, forbidden.body);
        let decrypted = f.call("POST", &format!("{}/decrypt", base), &decrypt_only, Some(input.clone())).await.ok();
        assert_eq!(decrypted["plaintext"], plain["plaintext"]);
        let allowed = f.call("POST", &format!("{}/rewrap", base), &both, Some(input.clone())).await.ok();
        assert_ne!(allowed["ciphertext"], input["ciphertext"]);
        let decoded = f.call("POST", &format!("{}/decrypt", base), &both, Some(json!({"ciphertext":allowed["ciphertext"],"context":"regression"}))).await.ok();
        assert_eq!(decoded["plaintext"], plain["plaintext"]);
        let denied = f.call("POST", &format!("{}/rewrap", base), &decrypt_only, Some(input.clone())).await;
        if denied.status != 403 { violations.push(format!("{} decrypt-only rewrap returned {} {}", kind, denied.status, denied.body)); }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

static SEQ: AtomicU32 = AtomicU32::new(0);
struct Native { child: Option<Child>, dir: PathBuf, base: String, client: reqwest::Client }
impl Drop for Native {
    fn drop(&mut self) { if let Some(mut child) = self.child.take() { let _ = child.kill(); let _ = child.wait(); } let _ = std::fs::remove_dir_all(&self.dir); }
}
impl Native {
    async fn new(f: &Fixture) -> Self {
        let dir = std::env::temp_dir().join(format!("openwarp-credential-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&format!("sqlite://{}", dir.join("test.db").display())).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&[7;32]))]).await.unwrap();
        db.exec("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await.unwrap();
        for table in ["orgs", "users", "org_members", "sessions", "identities", "apps", "envs"] {
            for row in f.state.db().query(&format!("SELECT * FROM {}", table), &[]).await.unwrap() {
                let columns: Vec<_> = row.keys().cloned().collect();
                let values: Vec<_> = columns.iter().map(|k| row[k].clone()).collect();
                db.exec(&format!("INSERT INTO {}({}) VALUES({})", table, columns.join(","), vec!["?"; columns.len()].join(",")), &values).await.unwrap();
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap(); drop(listener);
        let base = format!("http://{}", addr);
        let log = std::fs::File::create(dir.join("server.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_openwarp-server"))
            .env("DATABASE_URL", format!("sqlite://{}", dir.join("test.db").display())).env("ADDR", addr.to_string())
            .env("OPENWARP_ENV", "test").env("OPENWARP_PUBLIC_URL", &base).env("OPENWARP_ALLOW_PRIVATE_EGRESS", "1")
            .env("OPENWARP_AUTH_PROVIDERS", "password").env("TOKIO_WORKER_THREADS", "2")
            .env_remove("OPENWARP_MASTER_KEY").env_remove("OPENWARP_KMS_URL").env_remove("OPENWARP_KMS_TOKEN").env_remove("REDIS_URL")
            .stdout(Stdio::null()).stderr(Stdio::from(log)).spawn().unwrap();
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10)).build().unwrap();
        let mut server = Self { child: Some(child), dir, base, client };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() { panic!("server exited {}: {}", status, std::fs::read_to_string(server.dir.join("server.log")).unwrap()); }
            if let Ok(r) = server.client.get(format!("{}/health", server.base)).send().await { if r.status().is_success() { break; } }
            assert!(Instant::now() < deadline, "server startup timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        server
    }
    async fn call(&self, method: &str, path: &str, token: &str, body: Value) -> Reply {
        let mut request = self.client.request(method.parse().unwrap(), format!("{}{}", self.base, path)).json(&body);
        if !token.is_empty() { request = request.bearer_auth(token); }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        Reply { status, body: serde_json::from_str(&text).unwrap_or(json!(text)) }
    }
    fn token_count(&self) -> i64 {
        rusqlite::Connection::open(self.dir.join("test.db")).unwrap().query_row("SELECT count(*) FROM tokens", [], |r| r.get(0)).unwrap()
    }
}

#[tokio::test]
async fn alternate_valid_es256_signature_cannot_replay_one_workload_assertion() {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let signing = SigningKey::random(&mut rand_core::OsRng);
    let point = signing.verifying_key().to_encoded_point(false);
    let jwk = json!({"kty":"EC","crv":"P-256","kid":"local-es256","alg":"ES256","use":"sig","x":url64(point.x().unwrap()),"y":url64(point.y().unwrap())});
    let jwks = json!({"keys":[jwk.clone()]});
    let app = Router::new().route("/jwks", axum::routing::get(move || { let jwks = jwks.clone(); async move { axum::Json(jwks) } }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort { fn drop(&mut self) { self.0.abort(); } }
    let _issuer = Abort(task);
    let f = Fixture::new().await;
    let server = Native::new(&f).await;
    server.call("PUT", "/api/orgs/org/identities/machine/workload", "owner", json!({"issuer":issuer,"jwks_url":format!("{}/jwks", issuer),"audience":"openwarp","subject":"local-runner","max_ttl_secs":300})).await.ok();
    let header = json!({"alg":"ES256","typ":"JWT","kid":"local-es256"});
    let claims = json!({"iss":issuer,"aud":"openwarp","sub":"local-runner","iat":now(),"nbf":now()-1,"exp":now()+120,"jti":"one-assertion"});
    let input = format!("{}.{}", url64(header.to_string().as_bytes()), url64(claims.to_string().as_bytes()));
    let signature: Signature = signing.sign(input.as_bytes());
    let bytes = signature.to_bytes();
    // ECDSA accepts (r,s) and (r,n-s) for the same signed assertion.
    let order = rsa::BigUint::parse_bytes(b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16).unwrap();
    let alternate_s = (order - rsa::BigUint::from_bytes_be(&bytes[32..])).to_bytes_be();
    let mut alternate = bytes.to_vec();
    alternate[32..].fill(0);
    alternate[64-alternate_s.len()..].copy_from_slice(&alternate_s);
    Signature::from_slice(&alternate).unwrap();
    let first = format!("{}.{}", input, url64(&bytes));
    let second = format!("{}.{}", input, url64(&alternate));
    assert_ne!(first, second);
    let key = jsonwebtoken::DecodingKey::from_jwk(&serde_json::from_value(jwk).unwrap()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.leeway = 0; validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp","iat","iss","sub","aud"]);
    validation.set_issuer(&[issuer]); validation.set_audience(&["openwarp"]);
    for jwt in [&first, &second] {
        let verified = jsonwebtoken::decode::<Value>(jwt, &key, &validation).expect("both signature forms must pass the production JWT validator");
        assert_eq!(verified.claims, claims);
    }
    let endpoint = "/api/v1/machine/auth/workload/login";
    let before = server.token_count();
    let issued = server.call("POST", endpoint, "", json!({"identity_id":"machine","jwt":first})).await.ok();
    assert!(issued["accessToken"].as_str().is_some_and(|t| !t.is_empty()));
    assert_eq!(server.token_count(), before+1);
    let replay = server.call("POST", endpoint, "", json!({"identity_id":"machine","jwt":second})).await;
    let after = server.token_count();
    assert!(matches!(replay.status, 400 | 401 | 403 | 409) && after == before+1, "alternate signature replay returned {} {}, token count {} -> {} (only one token allowed)", replay.status, replay.body, before, after);
}

async fn v2_login(server: &Native) -> Reply {
    let challenge = server.call("POST", "/api/auth/challenge", "", json!({"email":"owner@test.invalid"})).await.ok();
    let id = challenge["challenge_id"].as_str().unwrap();
    let challenge = challenge["challenge"].as_str().unwrap();
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&[9;32]).unwrap();
    mac.update(format!("{}|{}", challenge, id).as_bytes());
    let proof: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    server.call("POST", "/api/auth/login-v2", "", json!({"email":"owner@test.invalid","challenge_id":id,"proof":proof})).await
}

#[tokio::test]
async fn native_master_rotation_preserves_v2_login_or_refuses_without_mutation() {
    let f = Fixture::new().await;
    let encrypted = oc::encrypt_symmetric_aad(&[7;32], b"auth-key|owner", &[9;32]);
    f.state.db().exec("UPDATE users SET auth_version=2,kdf_salt=?,kdf_iterations=600000,kdf_algo='pbkdf2-sha256',auth_key_enc=? WHERE id='owner'", &[json!(oc::b64(&[3;16])), json!(encrypted)]).await.unwrap();
    let server = Native::new(&f).await;
    let first = v2_login(&server).await.ok();
    let token = first["token"].as_str().expect("positive control issued a real v2 session");
    let conn = rusqlite::Connection::open(server.dir.join("test.db")).unwrap();
    let snapshot = || -> (String, String, Vec<(String, String)>) {
        let root = conn.query_row("SELECT v FROM meta WHERE k='master'", [], |r| r.get(0)).unwrap();
        let auth = conn.query_row("SELECT auth_key_enc FROM users WHERE id='owner'", [], |r| r.get(0)).unwrap();
        let envs = conn.prepare("SELECT id,env_key_wrapped FROM envs ORDER BY id").unwrap().query_map([], |r| Ok((r.get(0)?,r.get(1)?))).unwrap().map(Result::unwrap).collect();
        (root, auth, envs)
    };
    let before = snapshot();
    let rotated = server.call("POST", "/api/instance/rotate-master", token, json!({"new_key":oc::b64(&[6;32])})).await;
    assert!(matches!(rotated.status, 200 | 409), "rotation must succeed safely or explicitly refuse: {} {}", rotated.status, rotated.body);
    if rotated.status == 409 { assert_eq!(snapshot(), before, "refused rotation changed existing encrypted records"); }
    let login = v2_login(&server).await;
    assert_eq!(login.status, 200, "v2 login broke after rotation HTTP {}: {} (rotation returned {} {})", login.status, login.body, rotated.status, rotated.body);
    assert!(login.body["token"].as_str().is_some_and(|t| !t.is_empty()));
}
