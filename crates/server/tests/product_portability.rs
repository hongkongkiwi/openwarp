#![cfg(all(feature = "change-requests", feature = "workload-identity", feature = "transit"))]
use axum::{body::{to_bytes, Body}, http::{Method, Request}, Router};
use base64ct::{Base64UrlUnpadded, Encoding};
use openwarp_crypto as oc;
use openwarp_server::{app::{new_state, router, PeerAddr, S}, db::Db};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

const OWNER: &str = "portability-owner-session";
const ADMIN: &str = "portability-admin-session";
const LOGIN: &str = "/api/v1/machine/auth/workload/login";

struct Database { url: String, schema: Option<(String, String)>, directory: Option<std::path::PathBuf> }
impl Database {
    fn sqlite() -> Self {
        let directory = std::env::temp_dir().join(format!("openwarp-product-{}", oc::random_token("db")));
        std::fs::create_dir(&directory).expect("private test directory");
        Self { url: format!("sqlite://{}", directory.join("fixture.db").display()), schema: None, directory: Some(directory) }
    }
    async fn postgres() -> Option<Self> {
        let admin_url = match std::env::var("OPENWARP_TEST_POSTGRES_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => { eprintln!("SKIP PostgreSQL product portability: OPENWARP_TEST_POSTGRES_URL is not set"); return None; }
        };
        let schema = format!("ow_product_{}", oc::random_token("s").replace('-', "_").to_ascii_lowercase());
        let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.expect("connect test PostgreSQL");
        let driver = tokio::spawn(async move { connection.await.expect("PostgreSQL schema connection"); });
        admin.batch_execute(&format!("CREATE SCHEMA {}", schema)).await.expect("create owned test schema");
        drop(admin); driver.abort();
        let mut url = reqwest::Url::parse(&admin_url).expect("PostgreSQL URL");
        let pairs: Vec<(String, String)> = url.query_pairs().map(|(k,v)| (k.into_owned(), v.into_owned())).collect();
        let options = pairs.iter().filter(|(k,_)| k == "options").map(|(_,v)| v.as_str()).collect::<Vec<_>>().join(" ");
        url.set_query(None);
        for (k,v) in pairs.iter().filter(|(k,_)| k != "options") { url.query_pairs_mut().append_pair(k,v); }
        url.query_pairs_mut().append_pair("options", format!("{} -csearch_path={}", options, schema).trim());
        let encoded_query = url.query().unwrap_or("").replace('+', "%20");
        url.set_query(Some(&encoded_query));
        Some(Self { url: url.to_string(), schema: Some((admin_url, schema)), directory: None })
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        if let Some((admin_url, schema)) = self.schema.take() {
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread().enable_all().build().expect("cleanup runtime").block_on(async move {
                    let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.expect("connect for schema cleanup");
                    let driver = tokio::spawn(async move { let _ = connection.await; });
                    admin.batch_execute(&format!("DROP SCHEMA {} CASCADE", schema)).await.expect("drop only owned schema");
                    driver.abort();
                });
            }).join().expect("schema cleanup");
        }
        if let Some(directory) = self.directory.take() { std::fs::remove_dir_all(directory).expect("remove owned SQLite directory"); }
    }
}

struct Fixture { st: S, app: Router, org: String, dev: String, prod: String, identity: String }
struct Reply { status: u16, body: Value }
impl Fixture {
    async fn open(database: &Database, master: [u8;32], seed: bool, namespace: &str) -> Self {
        let db = Db::open(&database.url).await.expect("open isolated database and migrate");
        let (live, _) = tokio::sync::broadcast::channel(16);
        let st = new_state(db, database.url.clone(), namespace.into(), "https://openwarp.test.invalid".into(), master, live,
            #[cfg(feature = "redis-cache")] None);
        let f = Self { app: router(st.clone()), st, org: format!("{namespace}-org"), dev: format!("{namespace}-dev"), prod: format!("{namespace}-prod"), identity: format!("{namespace}-identity") };
        if seed {
            let owner = format!("{namespace}-owner"); let admin = format!("{namespace}-admin"); let app = format!("{namespace}-app");
            f.sql("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!(f.org),json!("portability"),json!(now())]).await;
            // This suite covers the gated surfaces, so the fixture workspace
            // holds every grant.
            f.sql("INSERT INTO feature_grants(org_id,features,updated_by,updated_at) VALUES(?,?,'fixture',?)",
                &[json!(f.org), json!("change-requests transit workload-identity pki ssh-ca saml scim ldap"), json!(now())]).await;
            for (uid, token, role) in [(&owner, OWNER, "owner"), (&admin, ADMIN, "admin")] {
                f.sql("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,?,'','',?,1,1)",
                    &[json!(uid),json!(format!("{uid}@test.invalid")),json!("unused-password-hash"),json!(now())]).await;
                f.sql("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!(f.org),json!(uid),json!(role)]).await;
                f.sql("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(token)),json!(uid),json!(now())]).await;
            }
            f.sql("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!(app),json!(f.org),json!("portability"),json!(now())]).await;
            for env in [&f.dev, &f.prod] {
                f.sql("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,?,?,?,?,?)", &[json!(env),json!(app),json!(env),json!(oc::encrypt_symmetric(&master, &[11;32])),json!("sse"),json!(now())]).await;
            }
            f.sql("INSERT INTO identities(id,org_id,name,role,created_at) VALUES(?,?,?,?,?)", &[json!(f.identity),json!(f.org),json!("portability"),json!("developer"),json!(now())]).await;
            f.sql("INSERT INTO meta(k,v) VALUES('instance_owner',?)", &[json!(owner)]).await;
            f.sql("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&master))]).await;
        }
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
        Reply { status, body: serde_json::from_slice(&bytes).expect("JSON API response") }
    }
    async fn expect(&self, method: Method, path: &str, token: &str, body: Option<Value>, status: u16) -> Value {
        let r = self.call(method.clone(), path, Some(token), body).await;
        assert_eq!(r.status, status, "{} {}: error={}", method, path, r.body["error"]);
        if status >= 400 { assert!(r.body["error"].is_string()); }
        r.body
    }
    async fn put(&self, env: &str, value: &str) { self.expect(Method::PUT, &format!("/api/envs/{env}/secrets"), OWNER, Some(json!({"secrets":[{"key":"TARGET","value":value}]})), 200).await; }
    async fn secrets(&self, env: &str) -> Value { self.expect(Method::GET, &format!("/api/envs/{env}/secrets"), OWNER, None, 200).await["secrets"].clone() }
    fn keys(&self) -> String { format!("/api/orgs/{}/transit/keys", self.org) }
    async fn transit(&self, key: &str, action: &str, body: Value) -> Value { self.expect(Method::POST, &format!("{}/{key}/{action}", self.keys()), OWNER, Some(body), 200).await }
}
fn now() -> i64 { openwarp_server::clock::now() }
fn identifier(v: &Value) -> String { v["id"].as_str().expect("response id").into() }

async fn stale_batch(f: &Fixture) {
    f.put(&f.dev, "before-dev").await; f.put(&f.prod, "before-prod").await;
    let path = format!("/api/orgs/{}/change-requests", f.org);
    let body = json!({"title":"portable batch", "changes":[
        {"env_id":f.dev,"secrets":[{"key":"TARGET","value":"after-dev"}],"deletes":[]},
        {"env_id":f.prod,"secrets":[{"key":"TARGET","value":"after-prod"}],"deletes":[]}]});
    let id = identifier(&f.expect(Method::POST, &path, OWNER, Some(body.clone()), 200).await);
    let action = format!("/api/change-requests/{id}");
    f.expect(Method::POST, &format!("{action}/approve"), ADMIN, Some(json!({"revision":1})), 200).await;
    f.put(&f.prod, "external-update").await;
    let dev = f.secrets(&f.dev).await; let prod = f.secrets(&f.prod).await;
    f.expect(Method::POST, &format!("{action}/apply"), ADMIN, Some(json!({"revision":1})), 409).await;
    assert_eq!(f.secrets(&f.dev).await, dev, "earlier environment must roll back");
    assert_eq!(f.secrets(&f.prod).await, prod, "conflicting environment must stay unchanged");
    assert_eq!(f.expect(Method::GET, &action, OWNER, None, 200).await["status"], "approved");
    let mut rebased = body; rebased["revision"] = json!(1);
    f.expect(Method::PUT, &action, OWNER, Some(rebased), 200).await;
    f.expect(Method::POST, &format!("{action}/approve"), ADMIN, Some(json!({"revision":2})), 200).await;
    f.expect(Method::POST, &format!("{action}/apply"), ADMIN, Some(json!({"revision":2})), 200).await;
    assert_eq!(f.secrets(&f.dev).await[0]["value"], "after-dev");
    assert_eq!(f.secrets(&f.prod).await[0]["value"], "after-prod");
    f.expect(Method::POST, &format!("{action}/apply"), ADMIN, Some(json!({"revision":2})), 409).await;
}

async fn concurrent_workload(f: &Fixture, other: &Fixture) {
    let signing = SigningKey::from_slice(&[1;32]).unwrap(); let point = signing.verifying_key().to_encoded_point(false);
    let enc = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
    let trust = identifier(&f.expect(Method::POST, &format!("/api/orgs/{}/identities/{}/workload-trust", f.org, f.identity), OWNER, Some(json!({
        "issuer":"https://issuer.test.invalid","audience":"portability","subject":"portability-job","env_id":f.dev,"scopes":["secrets:read"],"ttl":300,
        "jwks":{"keys":[{"kty":"EC","crv":"P-256","kid":"test","alg":"ES256","use":"sig","key_ops":["verify"],"x":enc(point.x().unwrap()),"y":enc(point.y().unwrap())}]}
    })), 200).await);
    let claims = json!({"iss":"https://issuer.test.invalid","aud":"portability","sub":"portability-job","jti":oc::random_token("jti"),"iat":now(),"exp":now()+300});
    let message = format!("{}.{}", enc(br#"{"alg":"ES256","kid":"test","typ":"JWT"}"#), enc(claims.to_string().as_bytes()));
    let sig: Signature = signing.sign(message.as_bytes()); let jwt = format!("{}.{}", message, enc(&sig.to_bytes()));
    let body = json!({"trust_id":trust,"jwt":jwt});
    let (a,b) = tokio::join!(f.call(Method::POST, LOGIN, None, Some(body.clone())), other.call(Method::POST, LOGIN, None, Some(body.clone())));
    let mut statuses = [a.status,b.status]; statuses.sort_unstable(); assert_eq!(statuses, [200,401], "exactly one concurrent exchange wins");
    let winner = if a.status == 200 { a } else { b };
    let token = winner.body["accessToken"].as_str().expect("usable winner token");
    f.expect(Method::GET, &format!("/api/envs/{}/secrets", f.dev), token, None, 200).await;
    f.expect(Method::GET, &format!("/api/envs/{}/secrets", f.prod), token, None, 403).await;
    assert_eq!(f.call(Method::POST, LOGIN, None, Some(body)).await.status, 401, "replay remains spent");
}

async fn transit_lifecycle(database: &Database, f: Fixture, other: Fixture, namespace: &str) {
    let key = identifier(&f.expect(Method::POST, &f.keys(), OWNER, Some(json!({"name":"portable"})), 200).await);
    let plain = oc::b64(b"portable transit payload\0binary");
    let input = json!({"plaintext":plain,"context":"portable-context"});
    let original = f.transit(&key, "encrypt", input.clone()).await;
    assert_eq!(original["version"], 1);
    let path = format!("{}/{key}/rotate", f.keys());
    let (a,b) = tokio::join!(f.call(Method::POST, &path, Some(OWNER), Some(json!({}))), other.call(Method::POST, &path, Some(OWNER), Some(json!({}))));
    let mut versions = Vec::new();
    for reply in [a,b] { match reply.status { 200 => versions.push(reply.body["current_version"].as_i64().expect("rotated version")), 409 => assert!(reply.body["error"].is_string()), status => panic!("unexpected rotation status {status}") } }
    versions.sort_unstable(); assert!(versions == [2] || versions == [2,3], "rotations must be a single CAS winner or distinct sequential versions");
    let latest = f.transit(&key, "encrypt", input).await;
    assert_eq!(latest["version"].as_i64(), versions.last().copied());
    let old = json!({"ciphertext":original["ciphertext"],"context":"portable-context"});
    let new = json!({"ciphertext":latest["ciphertext"],"context":"portable-context"});
    assert_eq!(f.transit(&key, "decrypt", old.clone()).await["plaintext"], plain);
    f.expect(Method::POST, "/api/instance/rotate-master", OWNER, Some(json!({"new_key":oc::b64(&[9;32])})), 200).await;
    drop(f); drop(other);
    let restarted = Fixture::open(database, [9;32], false, namespace).await;
    assert_eq!(restarted.transit(&key, "decrypt", old.clone()).await["plaintext"], plain, "original ciphertext survives fresh state and connection");
    assert_eq!(restarted.transit(&key, "decrypt", new.clone()).await["plaintext"], plain);
    let stale = Fixture::open(database, [7;32], false, namespace).await;
    let path = format!("{}/{key}/decrypt", stale.keys());
    let denied = stale.call(Method::POST, &path, Some(OWNER), Some(old.clone())).await;
    assert_eq!(denied.status, 409, "old master state must fail closed"); assert!(denied.body["error"].is_string());
    assert!(denied.body.get("plaintext").is_none());
    assert_eq!(restarted.transit(&key, "decrypt", old).await["plaintext"], plain, "stale read must not damage the new generation");
}

async fn lifecycle(database: Database) {
    let namespace = oc::random_token("fixture");
    let f = Fixture::open(&database, [7;32], true, &namespace).await;
    stale_batch(&f).await;
    let other = Fixture::open(&database, [7;32], false, &namespace).await;
    concurrent_workload(&f, &other).await;
    transit_lifecycle(&database, f, other, &namespace).await;
}
#[tokio::test]
async fn sqlite_disk_product_atomicity_concurrency_and_restart() { lifecycle(Database::sqlite()).await; }
#[tokio::test]
async fn postgres_product_atomicity_concurrency_and_restart() { if let Some(database) = Database::postgres().await { lifecycle(database).await; } }
