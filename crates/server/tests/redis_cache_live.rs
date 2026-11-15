#![cfg(all(feature = "redis-cache", not(target_arch = "wasm32")))]

use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}, Router};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, PeerAddr, S};
use redis::{Commands, Connection, ConnectionAddr};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const TTL_SECS: u64 = 300;

fn local_redis_client() -> redis::Client {
    let url = std::env::var("REDIS_URL").expect(
        "redis_cache_live with redis-cache requires REDIS_URL for an authorized disposable loopback Redis instance",
    );
    let client = redis::Client::open(url.as_str()).unwrap_or_else(|_| panic!("invalid local test REDIS_URL"));
    let info = client.get_connection_info();
    assert!(info.redis.username.is_none() && info.redis.password.is_none(), "live Redis fixture refuses credentials");
    let loopback = match &info.addr {
        ConnectionAddr::Tcp(host, _) => host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        _ => false,
    };
    assert!(loopback, "live Redis fixture requires a numeric loopback TCP address, not a deployment endpoint");
    client
}

fn connect(client: &redis::Client) -> Connection {
    let timeout = Duration::from_secs(5);
    let connection = client.get_connection_with_timeout(timeout).unwrap_or_else(|_| panic!("connect to local test Redis"));
    connection.set_read_timeout(Some(timeout)).unwrap_or_else(|_| panic!("bound Redis read time"));
    connection.set_write_timeout(Some(timeout)).unwrap_or_else(|_| panic!("bound Redis write time"));
    connection
}

struct RevocationKey { connection: Connection, key: String }
impl Drop for RevocationKey {
    fn drop(&mut self) {
        let removed: redis::RedisResult<u64> = self.connection.del(&self.key);
        if removed.is_err() { eprintln!("live Redis fixture could not clean its own expiring key"); }
    }
}

struct Fixture { state: S, app: Router, victim: String, control: String }
impl Fixture {
    async fn new(connection: Connection, victim: String) -> Self {
        let db = Db::open_memory().await.expect("private SQLite fixture");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let control = oc::random_token("redis_live_control");
        // Direct state isolates the cache contract; signup and mail delivery are covered by accounts.rs.
        for (uid, token) in [("cache-victim", victim.as_str()), ("cache-control", control.as_str())] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,'unused','unused','unused',?,1,1)",
                &[json!(uid), json!(format!("{uid}@example.invalid")), json!(now)]).await.expect("verified active fixture user");
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
                &[json!(oc::hash_token(token)), json!(uid), json!(now)]).await.expect("current fixture session");
        }
        let (live, _) = tokio::sync::broadcast::channel(8);
        let state = new_state(db, "sqlite::memory:".into(), "redis-cache-live".into(), "https://openwarp.test".into(), oc::random_key(), live, Some(connection));
        let app = router(state.clone());
        Self { state, app, victim, control }
    }

    async fn assert_auth(&self, token: &str, user: &str, expected: StatusCode) {
        for cookie in [false, true] {
            let (header, value) = if cookie { ("cookie", format!("ow_session={token}")) } else { ("authorization", format!("Bearer {token}")) };
            let request = Request::builder().uri("/api/me").header("host", "openwarp.test").header(header, value)
                .extension(PeerAddr(IpAddr::from([127, 0, 0, 1]))).body(Body::empty()).expect("fixture request");
            let response = self.app.clone().oneshot(request).await.expect("fixture response");
            assert_eq!(response.status(), expected, "unexpected /api/me status for {} authentication", if cookie { "cookie" } else { "bearer" });
            if expected == StatusCode::OK {
                let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("bounded profile body");
                let body: Value = serde_json::from_slice(&bytes).expect("profile JSON");
                assert!(body["id"].as_str() == Some(user), "authenticated profile must match the fixture account");
            }
        }
    }

    async fn assert_victim_persisted(&self) {
        let row = self.state.db().one("SELECT user_id FROM sessions WHERE token_hash=?", &[json!(oc::hash_token(&self.victim))])
            .await.expect("read persisted fixture session");
        assert!(row.is_some_and(|r| r["user_id"] == "cache-victim"), "Redis denial must leave the valid database session intact");
    }
}

#[tokio::test]
async fn live_redis_revocation_denies_bearer_and_cookie_without_deleting_the_database_session() {
    let client = local_redis_client();
    let mut connection = connect(&client);
    let pong: String = redis::cmd("PING").query(&mut connection).unwrap_or_else(|_| panic!("local test Redis must answer PING"));
    assert_eq!(pong, "PONG");
    let victim = oc::random_token("redis_live_victim");
    let key = format!("revoked:{}", oc::hash_token(&victim));
    let existing: Option<String> = connection.get(&key).unwrap_or_else(|_| panic!("read unique fixture revocation key"));
    assert!(existing.is_none(), "random fixture key must not already exist");
    let mut cache = RevocationKey { connection, key };
    let fixture = Fixture::new(connect(&client), victim).await;

    fixture.assert_auth(&fixture.victim, "cache-victim", StatusCode::OK).await;
    fixture.assert_auth(&fixture.control, "cache-control", StatusCode::OK).await;
    fixture.assert_victim_persisted().await;

    let written: redis::RedisResult<()> = cache.connection.set_ex(&cache.key, "1", TTL_SECS);
    assert!(written.is_ok(), "SETEX must succeed on actual Redis");
    let value: Option<String> = cache.connection.get(&cache.key).unwrap_or_else(|_| panic!("GET fixture revocation marker"));
    assert!(value.as_deref() == Some("1"), "GET must observe the SETEX marker");
    let ttl: i64 = cache.connection.ttl(&cache.key).unwrap_or_else(|_| panic!("TTL fixture revocation marker"));
    assert!(ttl > 0 && ttl <= TTL_SECS as i64, "revocation marker must have a bounded positive TTL");

    fixture.assert_auth(&fixture.victim, "cache-victim", StatusCode::UNAUTHORIZED).await;
    fixture.assert_victim_persisted().await;
    fixture.assert_auth(&fixture.control, "cache-control", StatusCode::OK).await;

    let removed: u64 = cache.connection.del(&cache.key).unwrap_or_else(|_| panic!("delete only the fixture revocation key"));
    assert_eq!(removed, 1, "cleanup must remove the fixture marker");
    let remaining: Option<String> = cache.connection.get(&cache.key).unwrap_or_else(|_| panic!("verify fixture key cleanup"));
    assert!(remaining.is_none(), "fixture marker must be removed");
    let ttl: i64 = cache.connection.ttl(&cache.key).unwrap_or_else(|_| panic!("verify removed fixture key TTL"));
    assert_eq!(ttl, -2, "removed fixture key must not exist");
    fixture.assert_auth(&fixture.victim, "cache-victim", StatusCode::OK).await;
    fixture.assert_victim_persisted().await;

    // A cache miss never grants access after the database session is gone.
    let removed = fixture.state.db().exec("DELETE FROM sessions WHERE token_hash=?", &[json!(oc::hash_token(&fixture.victim))])
        .await.expect("delete private fixture session");
    assert_eq!(removed, 1);
    fixture.assert_auth(&fixture.victim, "cache-victim", StatusCode::UNAUTHORIZED).await;
    fixture.assert_auth(&fixture.control, "cache-control", StatusCode::OK).await;
}
