use axum::{body::{to_bytes, Body}, http::{Method, Request}, Router};
use base64ct::{Base64UrlUnpadded, Encoding};
use openwarp_crypto as oc;
use openwarp_server::{app::{new_state, router, PeerAddr, S}, db::Db};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

/// These suites exercise surfaces that are compiled out by default. Returning
/// early keeps a core-only build green instead of failing on a missing route;
/// the all-features job is what actually exercises them.
fn suite_gated() -> bool { cfg!(all(feature = "change-requests", feature = "workload-identity", feature = "transit")) }

const OWNER: &str = "fixture-owner-session";
const ADMIN: &str = "fixture-admin-session";
const DEVELOPER: &str = "fixture-developer-session";
const OUTSIDER: &str = "fixture-outsider-session";
const READER: &str = "fixture-reader-session";
const WRITER: &str = "fixture-writer-session";
const REWRAPPER: &str = "fixture-rewrapper-session";
const ENCRYPTER: &str = "fixture-encrypter-session";
const LOGIN: &str = "/api/v1/machine/auth/workload/login";
const TRUSTS: &str = "/api/orgs/org-a/identities/identity-a/workload-trust";
const KEYS: &str = "/api/orgs/org-a/transit/keys";

struct Fixture { st: S, app: Router }
struct Reply { status: u16, body: Value }
impl Fixture {
    async fn new() -> Self {
        let db = Db::open_memory().await.expect("isolated database and migrations");
        let (live, _) = tokio::sync::broadcast::channel(16);
        let st = new_state(db, ":memory:".into(), "fixture-instance".into(), "https://openwarp.test.invalid".into(), [7; 32], live,
            #[cfg(feature = "redis-cache")] None);
        let f = Self { app: router(st.clone()), st };
        for org in ["org-a", "org-b"] {
            f.sql("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(org), json!(org), json!(now())]).await;
            // The fixture workspaces hold every grant: these suites test the
            // gated surfaces themselves, and the grant gate has its own test.
            let held = ["change-requests", "transit", "workload-identity", "pki", "ssh-ca", "saml", "scim", "ldap"].join(" ");
            f.sql("INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,'fixture',?)",
                &[json!(org), json!(&held), json!(now())]).await;
        }
        for (uid, token, org, role) in [
            ("owner", OWNER, "org-a", "owner"), ("admin", ADMIN, "org-a", "admin"),
            ("developer", DEVELOPER, "org-a", "developer"), ("outsider", OUTSIDER, "org-b", "owner"),
            ("reader", READER, "org-a", "reader"), ("writer", WRITER, "org-a", "writer"),
            ("rewrapper", REWRAPPER, "org-a", "rewrapper"), ("encrypter", ENCRYPTER, "org-a", "encrypter"),
        ] {
            f.sql("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,?,'','',?,1,1)",
                &[json!(uid), json!(format!("{}@test.invalid", uid)), json!("unused-password-hash"), json!(now())]).await;
            f.sql("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(org), json!(uid), json!(role)]).await;
            f.sql("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(token)), json!(uid), json!(now())]).await;
        }
        for (role, perms) in [
            ("reader", json!(["secrets:read"])), ("writer", json!(["secrets:write", "proposals:write"])),
            ("rewrapper", json!(["transit:rewrap"])), ("encrypter", json!(["transit:encrypt"])),
        ] {
            f.sql("INSERT INTO roles(id,org_id,name,permissions) VALUES(?,'org-a',?,?)", &[json!(role), json!(role), json!(perms.to_string())]).await;
        }
        for (app, org) in [("app-a", "org-a"), ("app-b", "org-b")] {
            f.sql("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(app), json!(org), json!(app), json!(now())]).await;
        }
        for (env, app, mode) in [("dev", "app-a", "sse"), ("prod", "app-a", "sse"), ("foreign", "app-b", "sse"), ("e2e", "app-a", "e2e"), ("delegated", "app-a", "delegated")] {
            let wrapped = if mode == "sse" { oc::encrypt_symmetric(&[7; 32], &[11; 32]) } else { String::new() };
            f.sql("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,?,?,?)", &[json!(env), json!(app), json!(env), json!(wrapped), json!(mode), json!(now())]).await;
        }
        for (iid, org, role) in [("identity-a", "org-a", "developer"), ("identity-b", "org-b", "developer"), ("identity-admin", "org-a", "admin")] {
            f.sql("INSERT INTO identities(id,org_id,name,role,created_at) VALUES(?,?,?,?,?)", &[json!(iid), json!(org), json!(iid), json!(role), json!(now())]).await;
        }
        f.sql("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await;
        f.sql("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&[7; 32]))]).await;
        f.expect(Method::GET, "/api/envs/dev/secrets", Some(OWNER), None, 200).await;
        f
    }
    async fn sql(&self, sql: &str, params: &[Value]) { self.st.db().exec(sql, params).await.expect("seed fixture"); }
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Reply {
        let mut req = Request::builder().method(method).uri(path).header("host", "openwarp.test.invalid");
        if let Some(token) = token { req = req.header("authorization", format!("Bearer {}", token)); }
        if body.is_some() { req = req.header("content-type", "application/json"); }
        let mut req = req.body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty)).unwrap();
        req.extensions_mut().insert(PeerAddr("192.0.2.10".parse().unwrap()));
        let response = self.app.clone().oneshot(req).await.expect("in-process request");
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024).await.expect("response body");
        Reply { status, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
    }
    async fn expect(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>, status: u16) -> Value {
        let r = self.call(method.clone(), path, token, body).await;
        assert_eq!(r.status, status, "{} {}: error={}", method, path, r.body["error"]);
        if status >= 400 { assert!(r.body["error"].is_string(), "denial must be an API error, not a route fallback"); }
        r.body
    }
    async fn put(&self, env: &str, secrets: Value) {
        self.expect(Method::PUT, &format!("/api/envs/{}/secrets", env), Some(OWNER), Some(json!({"secrets": secrets})), 200).await;
    }
    async fn secrets(&self, env: &str) -> Value {
        self.expect(Method::GET, &format!("/api/envs/{}/secrets", env), Some(OWNER), None, 200).await["secrets"].clone()
    }
    async fn create_change(&self, body: Value, author: &str) -> String {
        let r = self.expect(Method::POST, "/api/orgs/org-a/change-requests", Some(author), Some(body), 200).await;
        assert_eq!(r["revision"], 1); assert_eq!(r["status"], "pending");
        identifier(&r)
    }
    async fn change_action(&self, id: &str, action: &str, revision: i64, token: &str, status: u16) -> Value {
        self.expect(Method::POST, &format!("/api/change-requests/{}/{}", id, action), Some(token), Some(json!({"revision": revision})), status).await
    }
    async fn change(&self, id: &str) -> Value {
        self.expect(Method::GET, &format!("/api/change-requests/{}", id), Some(OWNER), None, 200).await
    }
    async fn trust(&self, body: Value, token: &str) -> String {
        identifier(&self.expect(Method::POST, TRUSTS, Some(token), Some(body), 200).await)
    }
    async fn exchange(&self, trust: &str, jwt: &str, status: u16) -> Value {
        self.expect(Method::POST, LOGIN, None, Some(json!({"trust_id": trust, "jwt": jwt})), status).await
    }
    async fn transit_key(&self, name: &str, org: &str, token: &str) -> String {
        identifier(&self.expect(Method::POST, &format!("/api/orgs/{}/transit/keys", org), Some(token), Some(json!({"name": name})), 200).await)
    }
    async fn transit(&self, key: &str, action: &str, token: &str, body: Value, status: u16) -> Value {
        self.expect(Method::POST, &format!("{}/{}/{}", KEYS, key, action), Some(token), Some(body), status).await
    }
    async fn pat(&self, token: &str, env: &str, scopes: &str) {
        self.sql("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,role,scopes,created_at,created_by) VALUES(?,'org-a','app-a',?,'fixture',?,'owner',?,?,'owner')",
            &[json!(token), json!(env), json!(oc::hash_token(token)), json!(scopes), json!(now())]).await;
    }
}
fn now() -> i64 { openwarp_server::clock::now() }
fn identifier(v: &Value) -> String { let id = v["id"].as_str().expect("response id"); assert!(!id.is_empty()); id.to_string() }
fn batch() -> Value {
    json!({"title": "Release reviewed configuration", "changes": [
        {"env_id": "dev", "secrets": [{"key": " api_key ", "value": "reviewed-dev", "path": "/service", "comment": "reviewed", "tags": "release"}], "deletes": []},
        {"env_id": "prod", "secrets": [{"key": "API_KEY", "value": "reviewed-prod"}], "deletes": [{"key": "OBSOLETE", "path": "/"}]}
    ]})
}
fn secret<'a>(items: &'a Value, key: &str, path: &str) -> &'a Value {
    items.as_array().unwrap().iter().find(|s| s["key"] == key && s["path"] == path).expect("expected logical secret")
}

#[tokio::test]
async fn change_request_approval_is_separate_from_atomic_cross_environment_apply() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    f.put("dev", json!([{"key":"API_KEY","value":"old-dev","path":"/service"}])).await;
    f.put("prod", json!([{"key":"API_KEY","value":"old-prod"},{"key":"OBSOLETE","value":"old"}])).await;
    let before_dev = f.secrets("dev").await; let before_prod = f.secrets("prod").await;
    let id = f.create_change(batch(), OWNER).await;
    f.change_action(&id, "approve", 1, OWNER, 403).await;
    f.change_action(&id, "apply", 1, ADMIN, 409).await;
    f.change_action(&id, "approve", 1, ADMIN, 200).await;
    assert_eq!(f.change(&id).await["status"], "approved");
    assert_eq!(f.secrets("dev").await, before_dev); assert_eq!(f.secrets("prod").await, before_prod);
    f.change_action(&id, "apply", 1, OWNER, 403).await;
    let result = f.change_action(&id, "apply", 1, ADMIN, 200).await;
    assert!(result.to_string().contains("sync_errors"), "apply must report provider outcomes");
    assert_eq!(f.change(&id).await["status"], "applied");
    let dev = f.secrets("dev").await; let prod = f.secrets("prod").await;
    let changed = secret(&dev, "API_KEY", "/service");
    assert_eq!(changed["value"], "reviewed-dev"); assert_eq!(changed["version"], 2);
    assert_eq!(changed["comment"], "reviewed"); assert_eq!(changed["tags"], "release");
    assert_eq!(secret(&prod, "API_KEY", "/")["value"], "reviewed-prod");
    assert!(!prod.as_array().unwrap().iter().any(|s| s["key"] == "OBSOLETE"));
    f.change_action(&id, "apply", 1, ADMIN, 409).await;
    assert_eq!(f.secrets("dev").await, dev); assert_eq!(f.secrets("prod").await, prod);
}

#[tokio::test]
async fn editing_a_change_request_cas_clears_approval_and_rebases_the_snapshot() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    f.put("prod", json!([{"key":"OBSOLETE","value":"old"}])).await;
    let id = f.create_change(batch(), OWNER).await;
    f.change_action(&id, "approve", 1, ADMIN, 200).await;
    let path = format!("/api/change-requests/{}", id);
    let mut edit = batch(); edit["revision"] = json!(1);
    f.expect(Method::PUT, &path, Some(ADMIN), Some(edit.clone()), 403).await;
    f.put("dev", json!([{"key":"API_KEY","value":"concurrent","path":"/service"}])).await;
    let edited = f.expect(Method::PUT, &path, Some(OWNER), Some(edit.clone()), 200).await;
    assert_eq!(edited["revision"], 2); assert_eq!(edited["status"], "pending");
    let detail = f.change(&id).await;
    assert!(detail.to_string().contains("concurrent"), "edit rebases before values");
    f.expect(Method::PUT, &path, Some(OWNER), Some(edit), 409).await;
    f.change_action(&id, "approve", 1, ADMIN, 409).await;
    f.change_action(&id, "apply", 1, ADMIN, 409).await;
    f.change_action(&id, "apply", 2, ADMIN, 409).await;
    f.change_action(&id, "approve", 2, ADMIN, 200).await;
    f.change_action(&id, "apply", 2, ADMIN, 200).await;
    assert_eq!(secret(&f.secrets("dev").await, "API_KEY", "/service")["value"], "reviewed-dev");
    let rejected = f.create_change(json!({"title":"Do not deploy","changes":[{"env_id":"dev","secrets":[{"key":"NO","value":"never"}],"deletes":[]}]}), OWNER).await;
    f.change_action(&rejected, "reject", 1, ADMIN, 200).await;
    assert_eq!(f.change(&rejected).await["status"], "rejected");
    f.change_action(&rejected, "apply", 1, ADMIN, 409).await;
}

#[tokio::test]
async fn stale_change_targets_and_new_key_collisions_never_partially_apply() {
    if !suite_gated() { return; }
    for mutation in ["update", "delete", "recreate", "absent"] {
        let f = Fixture::new().await;
        f.put("dev", json!([{"key":"FIRST","value":"untouched"}])).await;
        f.put("prod", json!([{"key":"TARGET","value":"baseline"}])).await;
        let target = secret(&f.secrets("prod").await, "TARGET", "/")["id"].as_str().unwrap().to_string();
        let body = json!({"title":"Atomic batch", "changes":[
            {"env_id":"dev","secrets":[{"key":"FIRST","value":"must-not-land"}],"deletes":[]},
            {"env_id":"prod","secrets":[{"key":if mutation == "absent" {"NEW"} else {"TARGET"},"value":"desired"}],"deletes":[]}
        ]});
        let id = f.create_change(body, OWNER).await;
        f.change_action(&id, "approve", 1, ADMIN, 200).await;
        match mutation {
            "update" => f.put("prod", json!([{"key":"TARGET","value":"external-update"}])).await,
            "delete" | "recreate" => {
                f.expect(Method::DELETE, &format!("/api/secrets/{}", target), Some(OWNER), None, 200).await;
                if mutation == "recreate" { f.put("prod", json!([{"key":"TARGET","value":"baseline"}])).await; }
            }
            "absent" => f.put("prod", json!([{"key":"NEW","value":"external-insert"}])).await,
            _ => unreachable!(),
        }
        let dev = f.secrets("dev").await; let prod = f.secrets("prod").await;
        let versions = f.st.db().query("SELECT * FROM secret_versions ORDER BY id", &[]).await.unwrap();
        f.change_action(&id, "apply", 1, ADMIN, 409).await;
        assert_eq!(f.secrets("dev").await, dev, "{} must not partially write the first environment", mutation);
        assert_eq!(f.secrets("prod").await, prod, "{} must preserve the conflicting target", mutation);
        assert_eq!(f.st.db().query("SELECT * FROM secret_versions ORDER BY id", &[]).await.unwrap(), versions);
        assert_eq!(f.change(&id).await["status"], "approved");
    }
}

#[tokio::test]
async fn change_review_is_tenant_authorized_redacted_and_server_readable_only() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    f.put("dev", json!([{"key":"NORMAL","value":"visible-before"},{"key":"SEALED","value":"sealed-before-fixture","type":"sealed"}])).await;
    let stored = f.st.db().query("SELECT value_enc FROM secrets WHERE env_id='dev'", &[]).await.unwrap();
    let body = json!({"title":"Review privacy", "changes":[{"env_id":"dev","secrets":[
        {"key":"NORMAL","value":"visible-after"},{"key":"SEALED","value":"sealed-after-fixture","type":"sealed"}],"deletes":[]}]});
    let id = f.create_change(body.clone(), OWNER).await;
    let detail = f.change(&id).await;
    let text = detail.to_string();
    assert!(detail["changes"].is_array());
    assert!(text.contains("visible-before") && text.contains("visible-after"));
    for value in ["sealed-before-fixture", "sealed-after-fixture", "value_enc"] { assert!(!text.contains(value), "review leaks sealed material or raw encrypted fields"); }
    for row in stored { assert!(!text.contains(row["value_enc"].as_str().unwrap()), "review must not substitute ciphertext for redaction"); }
    let list = f.expect(Method::GET, "/api/orgs/org-a/change-requests", Some(OWNER), None, 200).await;
    let listing = list.to_string(); assert!(listing.contains(&id));
    for value in ["visible-before", "visible-after", "sealed-before-fixture", "sealed-after-fixture", "changes"] { assert!(!listing.contains(value), "list is metadata only"); }
    f.expect(Method::GET, &format!("/api/change-requests/{}", id), Some(OUTSIDER), None, 403).await;
    f.expect(Method::GET, &format!("/api/change-requests/{}", id), Some(WRITER), None, 403).await;
    f.expect(Method::GET, "/api/orgs/org-a/change-requests", Some(OUTSIDER), None, 403).await;
    for env in ["e2e", "delegated"] {
        let mut encrypted = body.clone(); encrypted["changes"][0]["env_id"] = json!(env);
        f.expect(Method::POST, "/api/orgs/org-a/change-requests", Some(OWNER), Some(encrypted), 409).await;
    }
    let mut foreign = body.clone(); foreign["changes"][0]["env_id"] = json!("foreign");
    f.expect(Method::POST, "/api/orgs/org-a/change-requests", Some(OWNER), Some(foreign), 403).await;
    let mut duplicates = body.clone(); duplicates["changes"].as_array_mut().unwrap().push(body["changes"][0].clone());
    f.expect(Method::POST, "/api/orgs/org-a/change-requests", Some(OWNER), Some(duplicates), 400).await;
    f.expect(Method::POST, "/api/orgs/org-a/change-requests", Some(OWNER), Some(json!({"title":"empty","changes":[]})), 400).await;
    let mut invalid = body.clone(); invalid["changes"][0]["secrets"].as_array_mut().unwrap().push(json!({"key":"bad key","value":"invalid"}));
    f.expect(Method::POST, "/api/orgs/org-a/change-requests", Some(OWNER), Some(invalid), 400).await;
    assert_eq!(f.expect(Method::GET, "/api/orgs/org-a/change-requests", Some(OWNER), None, 200).await, list, "rejected inputs must not leave requests behind");
    f.sql("UPDATE envs SET restricted=1 WHERE id='dev'", &[]).await;
    f.expect(Method::GET, "/api/envs/prod/secrets", Some(READER), None, 200).await;
    f.expect(Method::GET, &format!("/api/change-requests/{}", id), Some(READER), None, 403).await;
    assert!(!f.expect(Method::GET, "/api/orgs/org-a/change-requests", Some(READER), None, 200).await.to_string().contains(&id));
}

fn signing_key(byte: u8) -> SigningKey { SigningKey::from_slice(&[byte; 32]).expect("fixed P-256 fixture scalar") }
fn b64url(bytes: &[u8]) -> String { Base64UrlUnpadded::encode_string(bytes) }
fn jwks() -> Value {
    let key = signing_key(1); let point = key.verifying_key().to_encoded_point(false);
    json!({"keys":[{"kty":"EC","crv":"P-256","kid":"fixture-key","use":"sig","alg":"ES256","key_ops":["verify"],"x":b64url(point.x().unwrap()),"y":b64url(point.y().unwrap())}]})
}
fn trust_body() -> Value {
    json!({"issuer":"https://issuer.test.invalid","audience":"openwarp-fixture","subject":"repo:fixture:environment:production","jwks":jwks(),"env_id":"dev","scopes":["secrets:read"],"ttl":300,"bound_claims":{"repository":"fixture/repo","ref":["refs/heads/main","release"]}})
}
fn claims(jti: &str) -> Value {
    let t = now();
    json!({"iss":"https://issuer.test.invalid","aud":"openwarp-fixture","sub":"repo:fixture:environment:production","exp":t+600,"iat":t,"jti":jti,"repository":"fixture/repo","ref":["refs/heads/main","release"]})
}
fn signed_with(claims: &Value, key: &SigningKey, extra_header: Value) -> String {
    let mut header = json!({"alg":"ES256","kid":"fixture-key","typ":"JWT"});
    for (k, v) in extra_header.as_object().unwrap() { header[k] = v.clone(); }
    let message = format!("{}.{}", b64url(header.to_string().as_bytes()), b64url(claims.to_string().as_bytes()));
    let sig: Signature = key.sign(message.as_bytes());
    format!("{}.{}", message, b64url(&sig.to_bytes()))
}
fn signed(claims: &Value) -> String { signed_with(claims, &signing_key(1), json!({})) }

#[test]
fn workload_es256_fixture_verifies_with_exported_public_jwk_and_rejects_wrong_key() {
    let public = jwks(); let jwk = &public["keys"][0];
    let key = jsonwebtoken::DecodingKey::from_ec_components(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap()).expect("exported public P-256 coordinates");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&["https://issuer.test.invalid"]);
    validation.set_audience(&["openwarp-fixture"]);
    let expected = claims("fixture-qualification");
    let proof = signed(&expected);
    let verified = jsonwebtoken::decode::<Value>(&proof, &key, &validation).expect("independent JWT verifier accepts the fixture");
    assert_eq!(verified.claims, expected);
    let wrong = signed_with(&expected, &signing_key(2), json!({}));
    let error = jsonwebtoken::decode::<Value>(&wrong, &key, &validation).expect_err("a different signing key must fail verification");
    assert_eq!(*error.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature);
}

fn access_token(v: &Value) -> &str {
    assert_eq!(v["tokenType"], "Bearer"); assert_eq!(v["identity_id"], "identity-a");
    assert!((1..=300).contains(&v["expiresIn"].as_i64().expect("bounded token lifetime")));
    let token = v["accessToken"].as_str().expect("accessToken"); assert!(!token.is_empty()); token
}

#[tokio::test]
async fn workload_exchange_scopes_tokens_and_revocation_is_immediate() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    f.put("dev", json!([{"key":"CONSUME","value":"workload-value"}])).await;
    let trust = f.trust(trust_body(), OWNER).await;
    let policy = f.expect(Method::GET, TRUSTS, Some(OWNER), None, 200).await;
    assert!(policy.to_string().contains(&trust));
    let jwt = signed(&claims("success"));
    let login = f.exchange(&trust, &jwt, 200).await;
    let token = access_token(&login);
    let data = f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 200).await;
    assert_eq!(secret(&data["secrets"], "CONSUME", "/")["value"], "workload-value");
    f.expect(Method::PUT, "/api/envs/dev/secrets", Some(token), Some(json!({"secrets":[{"key":"DENIED","value":"no"}]})), 403).await;
    f.expect(Method::GET, "/api/envs/prod/secrets", Some(token), None, 403).await;
    f.expect(Method::GET, "/api/envs/foreign/secrets", Some(token), None, 403).await;
    f.expect(Method::POST, "/api/orgs/org-a/identities", Some(token), Some(json!({"name":"escalation","role":"admin"})), 403).await;
    f.expect(Method::POST, "/api/apps/app-a/tokens", Some(token), Some(json!({"name":"escalation"})), 403).await;
    f.sql("INSERT INTO teams(id,org_id,name) VALUES('fixture-team','org-a','fixture')", &[]).await;
    f.expect(Method::POST, "/api/envs/prod/team-grants", Some(OWNER), Some(json!({"team_id":"fixture-team"})), 200).await;
    f.expect(Method::POST, "/api/envs/dev/team-grants", Some(token), Some(json!({"team_id":"fixture-team"})), 403).await;
    let mcp = f.call(Method::POST, "/mcp", Some(token), Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_secret","arguments":{"env_id":"dev","key":"DENIED","value":"no"}}}))).await;
    assert_ne!(mcp.status, 404);
    assert!(mcp.status == 403 || (mcp.status == 200 && (mcp.body["error"].is_object() || mcp.body["result"]["isError"] == true)), "read-only workload must not mutate through MCP");
    assert!(!f.secrets("dev").await.as_array().unwrap().iter().any(|s| s["key"] == "DENIED"));
    f.exchange(&trust, &jwt, 401).await;
    f.expect(Method::DELETE, &format!("{}/{}", TRUSTS, trust), Some(OWNER), None, 200).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 401).await;
    f.exchange(&trust, &signed(&claims("after-revoke")), 401).await;
}

#[tokio::test]
async fn workload_jwt_proofs_require_exact_claims_times_and_asymmetric_signatures() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    let trust = f.trust(trust_body(), OWNER).await;
    access_token(&f.exchange(&trust, &signed(&claims("control")), 200).await);
    let mut invalid = vec![Value::Null];
    for (field, value) in [
        ("iss", json!("https://issuer.test.invalid/")), ("aud", json!("other-audience")),
        ("sub", json!("repo:fixture:environment:*")), ("repository", json!("fixture/*")),
        ("ref", json!(["release", "refs/heads/main"])), ("exp", json!(now()-60)),
        ("iat", json!(now()+120)), ("nbf", json!(now()+120)),
    ] { let mut c = claims(field); c[field] = value; invalid.push(c); }
    for field in ["exp", "iat", "jti"] { let mut c = claims(field); c.as_object_mut().unwrap().remove(field); invalid.push(c); }
    let mut too_old = claims("old"); too_old["iat"] = json!(now()-1000); invalid.push(too_old);
    let mut too_long = claims("long"); too_long["exp"] = json!(now()+3700); invalid.push(too_long);
    let generic = f.exchange(&trust, "not-a-jwt", 401).await;
    assert!(generic["error"].is_string());
    for c in invalid {
        let r = f.exchange(&trust, &signed(&c), 401).await;
        assert_eq!(r["error"], generic["error"], "invalid proof errors must not disclose which claim failed");
    }
    for jwt in [
        signed_with(&claims("wrong-key"), &signing_key(2), json!({})),
        signed_with(&claims("unknown-kid"), &signing_key(1), json!({"kid":"unknown"})),
        signed_with(&claims("jku"), &signing_key(1), json!({"jku":"https://keys.test.invalid/jwks"})),
        signed_with(&claims("x5u"), &signing_key(1), json!({"x5u":"https://keys.test.invalid/cert"})),
        signed_with(&claims("none"), &signing_key(1), json!({"alg":"none"})),
        jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256), &claims("hmac"), &jsonwebtoken::EncodingKey::from_secret(b"fixture-shared-secret")).unwrap(),
    ] { assert_eq!(f.exchange(&trust, &jwt, 401).await["error"], generic["error"]); }
    f.expect(Method::POST, LOGIN, None, Some(json!({"trust_id":trust})), 401).await;
    let mut short = claims("short-proof"); short["exp"] = json!(now()+90);
    let limited = f.exchange(&trust, &signed(&short), 200).await;
    access_token(&limited); assert!(limited["expiresIn"].as_i64().unwrap() <= 90);
}

#[tokio::test]
async fn workload_trust_configuration_checks_tenants_roles_public_keys_and_scope() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    let trust = f.trust(trust_body(), ADMIN).await;
    access_token(&f.exchange(&trust, &signed(&claims("configuration-control")), 200).await);
    for token in [DEVELOPER, OUTSIDER] { f.expect(Method::POST, TRUSTS, Some(token), Some(trust_body()), 403).await; }
    f.expect(Method::GET, TRUSTS, Some(OUTSIDER), None, 403).await;
    f.expect(Method::DELETE, &format!("{}/{}", TRUSTS, trust), Some(OUTSIDER), None, 403).await;
    f.expect(Method::POST, "/api/orgs/org-a/identities/identity-b/workload-trust", Some(OWNER), Some(trust_body()), 403).await;
    let privileged = "/api/orgs/org-a/identities/identity-admin/workload-trust";
    f.expect(Method::POST, privileged, Some(OWNER), Some(trust_body()), 200).await;
    f.expect(Method::POST, privileged, Some(ADMIN), Some(trust_body()), 403).await;
    let mut foreign = trust_body(); foreign["env_id"] = json!("foreign");
    f.expect(Method::POST, TRUSTS, Some(OWNER), Some(foreign), 403).await;
    for (field, value) in [
        ("ttl", json!(29)), ("ttl", json!(901)), ("env_id", json!("")),
        ("scopes", json!([])), ("scopes", json!(["*"])), ("scopes", json!(["secrets:delete"])),
        ("bound_claims", json!({"sub":"forbidden-reserved-claim"})),
        ("jwks", json!({"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256"}]})),
    ] {
        let mut body = trust_body(); body[field] = value;
        f.expect(Method::POST, TRUSTS, Some(OWNER), Some(body), 400).await;
    }
    let mut missing_env = trust_body(); missing_env.as_object_mut().unwrap().remove("env_id");
    f.expect(Method::POST, TRUSTS, Some(OWNER), Some(missing_env), 400).await;
    let mut private = trust_body(); private["jwks"]["keys"][0]["d"] = json!(b64url(&[1;32]));
    f.expect(Method::POST, TRUSTS, Some(OWNER), Some(private), 400).await;
    for (field, value) in [("use", json!("enc")), ("key_ops", json!(["encrypt"])), ("alg", json!("RS256"))] {
        let mut body = trust_body(); body["jwks"]["keys"][0][field] = value;
        f.expect(Method::POST, TRUSTS, Some(OWNER), Some(body), 400).await;
    }
}

#[tokio::test]
async fn workload_replay_spans_trusts_and_live_identity_and_peer_policy_are_enforced() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    let first = f.trust(trust_body(), OWNER).await;
    let mut second_policy = trust_body(); second_policy["subject"] = json!("repo:fixture:environment:staging");
    let second = f.trust(second_policy, OWNER).await;
    let proof = claims("shared-jti");
    let login = f.exchange(&first, &signed(&proof), 200).await;
    let token = access_token(&login);
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 200).await;
    let mut replay = proof; replay["sub"] = json!("repo:fixture:environment:staging");
    f.exchange(&second, &signed(&replay), 401).await;
    f.sql("UPDATE orgs SET ip_allowlist='198.51.100.0/24' WHERE id='org-a'", &[]).await;
    f.exchange(&first, &signed(&claims("blocked-peer")), 403).await;
    f.sql("UPDATE orgs SET ip_allowlist='' WHERE id='org-a'", &[]).await;
    let after = f.exchange(&first, &signed(&claims("allowed-peer")), 200).await;
    access_token(&after);
    f.expect(Method::DELETE, "/api/orgs/org-a/identities/identity-a", Some(OWNER), None, 200).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 401).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(access_token(&after)), None, 401).await;
    f.exchange(&first, &signed(&claims("deleted-identity")), 401).await;
}

#[tokio::test]
async fn transit_versions_rewrap_without_plaintext_and_survive_master_rotation() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    let key = f.transit_key("payments.primary", "org-a", OWNER).await;
    let plain = oc::b64(b"transit fixture payload\0with binary");
    let input = json!({"plaintext":plain,"context":"payment:fixture"});
    let encrypted = f.transit(&key, "encrypt", OWNER, input.clone(), 200).await;
    assert_eq!(encrypted["version"], 1);
    assert!(encrypted["ciphertext"].as_str().unwrap().starts_with("owt1:"));
    let old = json!({"ciphertext":encrypted["ciphertext"],"context":"payment:fixture"});
    let decrypted = f.transit(&key, "decrypt", OWNER, old.clone(), 200).await;
    assert_eq!(decrypted["plaintext"], plain); assert_eq!(decrypted["version"], 1);
    f.transit(&key, "rotate", ADMIN, json!({}), 200).await;
    assert_eq!(f.transit(&key, "encrypt", OWNER, input, 200).await["version"], 2);
    assert_eq!(f.transit(&key, "decrypt", OWNER, old.clone(), 200).await["plaintext"], plain);
    let rewrapped = f.transit(&key, "rewrap", REWRAPPER, old.clone(), 200).await;
    assert_eq!(rewrapped["version"], 2); assert!(rewrapped.get("plaintext").is_none());
    assert!(!rewrapped.to_string().contains(&plain)); assert_ne!(rewrapped["ciphertext"], encrypted["ciphertext"]);
    f.transit(&key, "decrypt", REWRAPPER, old.clone(), 403).await;
    let latest = json!({"ciphertext":rewrapped["ciphertext"],"context":"payment:fixture"});
    assert_eq!(f.transit(&key, "decrypt", OWNER, latest.clone(), 200).await["plaintext"], plain);
    let listing = f.expect(Method::GET, KEYS, Some(OWNER), None, 200).await;
    let entries = listing.as_array().or_else(|| listing["keys"].as_array()).expect("key metadata list");
    let metadata = entries.iter().find(|v| v["id"] == key).expect("created key in list");
    assert_eq!(metadata["name"], "payments.primary"); assert_eq!(metadata["current_version"], 2);
    assert_eq!(metadata.as_object().unwrap().len(), 3, "only id, name, current_version are public");
    f.expect(Method::POST, "/api/instance/rotate-master", Some(OWNER), Some(json!({"new_key":oc::b64(&[9;32])})), 200).await;
    assert_eq!(f.transit(&key, "decrypt", OWNER, old, 200).await["plaintext"], plain);
    assert_eq!(f.transit(&key, "decrypt", OWNER, latest, 200).await["plaintext"], plain);
    let audits = f.st.db().query("SELECT detail FROM audit", &[]).await.unwrap();
    let audit = serde_json::to_string(&audits).unwrap();
    for sensitive in [&plain, "payment:fixture", encrypted["ciphertext"].as_str().unwrap(), rewrapped["ciphertext"].as_str().unwrap()] {
        assert!(!audit.contains(sensitive), "audit must not contain transit request material");
    }
}

#[tokio::test]
async fn transit_permissions_are_independent_and_env_tokens_cannot_escape_scope() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    let key = f.transit_key("permissions", "org-a", OWNER).await;
    let input = json!({"plaintext":oc::b64(b"permission fixture"),"context":""});
    let encrypted = f.transit(&key, "encrypt", ENCRYPTER, input.clone(), 200).await;
    let cipher = json!({"ciphertext":encrypted["ciphertext"],"context":""});
    f.transit(&key, "decrypt", OWNER, cipher.clone(), 200).await;
    f.transit(&key, "rewrap", REWRAPPER, cipher.clone(), 200).await;
    f.transit(&key, "decrypt", ENCRYPTER, cipher.clone(), 403).await;
    f.transit(&key, "rewrap", ENCRYPTER, cipher.clone(), 403).await;
    f.transit(&key, "encrypt", REWRAPPER, input.clone(), 403).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(READER), None, 200).await;
    f.transit(&key, "decrypt", READER, cipher.clone(), 403).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(DEVELOPER), None, 200).await;
    for (action, body) in [("encrypt", input.clone()), ("decrypt", cipher.clone()), ("rewrap", cipher.clone()), ("rotate", json!({}))] {
        f.transit(&key, action, DEVELOPER, body, 403).await;
    }
    f.expect(Method::POST, KEYS, Some(DEVELOPER), Some(json!({"name":"denied"})), 403).await;
    f.pat("env-pat", "dev", "secrets:read secrets:write").await;
    f.pat("write-pat", "", "secrets:read secrets:write").await;
    for token in ["env-pat", "write-pat"] {
        f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 200).await;
        for (action, body) in [("encrypt", input.clone()), ("decrypt", cipher.clone()), ("rewrap", cipher.clone()), ("rotate", json!({}))] {
            f.transit(&key, action, token, body, 403).await;
        }
    }
    // Main now binds OAuth tokens to the API audience; seed the instance URL.
    f.sql("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,expires_at,created_at) VALUES(?,'fixture-client','owner','secrets:read secrets:write','https://openwarp.test.invalid',?,?)",
        &[json!(oc::hash_token("oauth-secret-scopes")), json!(now()+300), json!(now())]).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some("oauth-secret-scopes"), None, 200).await;
    f.transit(&key, "decrypt", "oauth-secret-scopes", cipher, 403).await;
    f.transit(&key, "encrypt", "oauth-secret-scopes", input, 403).await;
}

#[tokio::test]
async fn transit_authenticates_context_key_and_tenant_and_rejects_malformed_inputs() {
    if !suite_gated() { return; }
    let f = Fixture::new().await;
    let key = f.transit_key("bound-key", "org-a", OWNER).await;
    let other = f.transit_key("other-key", "org-a", OWNER).await;
    let foreign = f.transit_key("bound-key", "org-b", OUTSIDER).await;
    let encrypted = f.transit(&key, "encrypt", OWNER, json!({"plaintext":oc::b64(b"bound payload"),"context":"bound-context"}), 200).await;
    let body = json!({"ciphertext":encrypted["ciphertext"],"context":"bound-context"});
    f.transit(&key, "decrypt", OWNER, body.clone(), 200).await;
    f.expect(Method::GET, "/api/orgs/org-b/transit/keys", Some(OUTSIDER), None, 200).await;
    f.transit(&key, "decrypt", OUTSIDER, body.clone(), 403).await;
    f.expect(Method::POST, &format!("/api/orgs/org-b/transit/keys/{}/decrypt", foreign), Some(OUTSIDER), Some(body.clone()), 400).await;
    f.transit(&foreign, "decrypt", OWNER, body.clone(), 403).await;
    for action in ["decrypt", "rewrap"] {
        f.transit(&other, action, OWNER, body.clone(), 400).await;
        let mut wrong_context = body.clone(); wrong_context["context"] = json!("different-context");
        f.transit(&key, action, OWNER, wrong_context, 400).await;
        let mut tampered = body.clone();
        let mut bytes = tampered["ciphertext"].as_str().unwrap().as_bytes().to_vec();
        let n = bytes.len()/2; bytes[n] = if bytes[n] == b'A' { b'B' } else { b'A' };
        tampered["ciphertext"] = json!(String::from_utf8(bytes).unwrap());
        f.transit(&key, action, OWNER, tampered, 400).await;
    }
    for body in [json!({"plaintext":"not base64","context":""}), json!({"plaintext":oc::b64(b"x")}), json!({"plaintext":oc::b64(b"x"),"context":"x".repeat(1025)})] {
        f.transit(&key, "encrypt", OWNER, body, 400).await;
    }
    for name in ["", "bad/name", "white space", "nonascii-é"] {
        f.expect(Method::POST, KEYS, Some(OWNER), Some(json!({"name":name})), 400).await;
    }
    assert_eq!(f.transit(&key, "decrypt", OWNER, body, 200).await["plaintext"], oc::b64(b"bound payload"));
}
