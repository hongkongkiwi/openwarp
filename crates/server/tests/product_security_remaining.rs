include!("product_features.rs");

async fn remaining_history(f: &Fixture, sid: &str) -> Value {
    f.expect(Method::GET, &format!("/api/secrets/{sid}/history"), Some(OWNER), None, 200).await
}
async fn remaining_retention(f: &Fixture, env: &str, limit: i64) {
    f.expect(Method::PUT, &format!("/api/envs/{env}/policy"), Some(OWNER), Some(json!({"max_versions":limit})), 200).await;
    let meta = f.expect(Method::GET, &format!("/api/envs/{env}/meta"), Some(OWNER), None, 200).await;
    assert_eq!(meta["policy"]["max_versions"], limit, "policy must be configured through the public API");
}

#[tokio::test]
async fn remaining_batch_apply_obeys_retention_and_preserves_unlimited_history() {
    let f = Fixture::new().await;
    remaining_retention(&f, "dev", 1).await;
    remaining_retention(&f, "prod", 0).await;
    for env in ["dev", "prod"] { f.put(env, json!([{"key":"TARGET","value":"retention-v1"}])).await; }
    let dev = secret(&f.secrets("dev").await, "TARGET", "/")["id"].as_str().unwrap().to_string();
    let prod = secret(&f.secrets("prod").await, "TARGET", "/")["id"].as_str().unwrap().to_string();
    for sid in [&dev, &prod] { let h = remaining_history(&f, sid).await; assert_eq!(h.as_array().unwrap().len(), 1); assert_eq!(h[0]["version"], 1); }
    let id = f.create_change(json!({"title":"Retained batch", "changes":[
        {"env_id":"dev","secrets":[{"key":"TARGET","value":"retention-v2"}],"deletes":[]},
        {"env_id":"prod","secrets":[{"key":"TARGET","value":"retention-v2"}],"deletes":[]}
    ]}), OWNER).await;
    f.change_action(&id, "approve", 1, ADMIN, 200).await;
    f.change_action(&id, "apply", 1, ADMIN, 200).await;
    let unlimited = remaining_history(&f, &prod).await;
    assert_eq!(unlimited.as_array().unwrap().len(), 2, "max_versions=0 keeps both versions");
    assert_eq!(unlimited[0]["value"], "retention-v2"); assert_eq!(unlimited[1]["value"], "retention-v1");
    let retained = remaining_history(&f, &dev).await;
    assert_eq!(retained.as_array().unwrap().len(), 1, "batch apply must prune old versions under max_versions=1");
    assert_eq!(retained[0]["version"], 2); assert_eq!(retained[0]["value"], "retention-v2");
    assert!(!retained.to_string().contains("retention-v1"), "old plaintext must no longer be available from history");
    assert_eq!(secret(&f.secrets("dev").await, "TARGET", "/")["version"], 2);
}

#[tokio::test]
async fn remaining_rejected_batch_preserves_retained_history_and_current_values() {
    let f = Fixture::new().await;
    remaining_retention(&f, "dev", 1).await;
    for env in ["dev", "prod"] { f.put(env, json!([{"key":"TARGET","value":"retained-before"}])).await; }
    let sid = secret(&f.secrets("dev").await, "TARGET", "/")["id"].as_str().unwrap().to_string();
    let id = f.create_change(json!({"title":"Atomic retention", "changes":[
        {"env_id":"dev","secrets":[{"key":"TARGET","value":"must-not-land"}],"deletes":[]},
        {"env_id":"prod","secrets":[{"key":"TARGET","value":"must-not-land"}],"deletes":[]}
    ]}), OWNER).await;
    f.change_action(&id, "approve", 1, ADMIN, 200).await;
    f.put("prod", json!([{"key":"TARGET","value":"concurrent-value"}])).await;
    let before = f.secrets("dev").await; let prod = f.secrets("prod").await;
    let history = remaining_history(&f, &sid).await;
    f.change_action(&id, "apply", 1, ADMIN, 409).await;
    assert_eq!(f.secrets("dev").await, before);
    assert_eq!(f.secrets("prod").await, prod);
    assert_eq!(remaining_history(&f, &sid).await, history, "failed apply must neither prune nor append retained history");
    assert_eq!(f.change(&id).await["status"], "approved");
}

struct RemainingMysql { admin: String, name: String, url: String }
impl RemainingMysql {
    async fn new() -> Option<Self> {
        use mysql_async::prelude::Queryable;
        let admin = match std::env::var("OPENWARP_TEST_MYSQL_URL") {
            Ok(url) => { assert!(!url.trim().is_empty(), "provided OPENWARP_TEST_MYSQL_URL must not be empty"); url },
            Err(std::env::VarError::NotPresent) => { eprintln!("SKIP remaining MySQL regression: OPENWARP_TEST_MYSQL_URL is absent"); return None; },
            Err(_) => panic!("OPENWARP_TEST_MYSQL_URL must be valid Unicode"),
        };
        let opts = mysql_async::Opts::from_url(&admin).unwrap_or_else(|_| panic!("invalid MySQL test URL (redacted)"));
        let pool = mysql_async::Pool::new(opts);
        let mut conn = pool.get_conn().await.unwrap_or_else(|_| panic!("cannot connect to provided MySQL test database (URL redacted)"));
        let name = format!("ow_product_remaining_{}", oc::random_token("db").chars().take(24).collect::<String>().replace('-', "_").to_ascii_lowercase());
        conn.query_drop(format!("CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")).await.expect("create owned disposable MySQL database");
        drop(conn); pool.disconnect().await.expect("disconnect MySQL admin");
        let mut url = reqwest::Url::parse(&admin).unwrap_or_else(|_| panic!("invalid MySQL test URL (redacted)"));
        url.set_path(&format!("/{name}"));
        Some(Self { admin, name, url: url.to_string() })
    }
    async fn fixture(&self, master: [u8;32], seed: bool) -> Fixture {
        let db = Db::open(&self.url).await.unwrap_or_else(|_| panic!("open and migrate owned MySQL test database (URL redacted)"));
        let (live, _) = tokio::sync::broadcast::channel(16);
        let st = new_state(db, self.url.clone(), "remaining-mysql".into(), "https://openwarp.test.invalid".into(), master, live,
            #[cfg(feature = "redis-cache")] None);
        let f = Fixture { app: router(st.clone()), st };
        if seed {
            for (uid, token) in [("owner", OWNER), ("admin", ADMIN)] {
                f.sql("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,?,'','',?,1,1)", &[json!(uid),json!(format!("{uid}@test.invalid")),json!("unused-password-hash"),json!(now())]).await;
                f.sql("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(token)),json!(uid),json!(now())]).await;
            }
            f.sql("INSERT INTO orgs(id,name,created_at) VALUES('org-a','remaining',?)", &[json!(now())]).await;
            for (uid, role) in [("owner","owner"),("admin","admin")] { f.sql("INSERT INTO org_members(org_id,user_id,role) VALUES('org-a',?,?)", &[json!(uid),json!(role)]).await; }
            f.sql("INSERT INTO apps(id,org_id,name,created_at) VALUES('app-a','org-a','remaining',?)", &[json!(now())]).await;
            for env in ["dev", "prod"] { f.sql("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES(?,'app-a',?,?,'sse',?)", &[json!(env),json!(env),json!(oc::encrypt_symmetric(&master, &[11;32])),json!(now())]).await; }
            f.sql("INSERT INTO identities(id,org_id,name,role,created_at) VALUES('identity-a','org-a','remaining','developer',?)", &[json!(now())]).await;
            f.sql("INSERT INTO meta(k,v) VALUES('instance_owner','owner')", &[]).await;
            f.sql("INSERT INTO meta(k,v) VALUES('master',?)", &[json!(oc::b64(&master))]).await;
        }
        f
    }
}
impl Drop for RemainingMysql {
    fn drop(&mut self) {
        let admin = self.admin.clone(); let name = self.name.clone();
        std::thread::spawn(move || {
            use mysql_async::prelude::Queryable;
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("cleanup runtime").block_on(async move {
                let opts = mysql_async::Opts::from_url(&admin).unwrap_or_else(|_| panic!("invalid cleanup URL (redacted)"));
                let pool = mysql_async::Pool::new(opts);
                let mut conn = pool.get_conn().await.unwrap_or_else(|_| panic!("MySQL cleanup connection failed (URL redacted)"));
                conn.query_drop(format!("DROP DATABASE `{name}`")).await.expect("drop only owned test database");
                drop(conn); pool.disconnect().await.expect("disconnect cleanup pool");
            });
        }).join().expect("owned MySQL database cleanup");
    }
}

#[tokio::test]
async fn remaining_mysql_valid_signed_workload_exchange_is_not_rate_limited() {
    let Some(database) = RemainingMysql::new().await else { return; };
    let f = database.fixture([7;32], true).await;
    let trust = f.trust(trust_body(), OWNER).await;
    let jwt = signed(&claims("remaining-mysql-signed-job"));
    let exchange = f.exchange(&trust, &jwt, 200).await;
    let token = exchange["accessToken"].as_str().expect("workload exchange returns a token");
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 200).await;
    f.expect(Method::GET, "/api/envs/prod/secrets", Some(token), None, 403).await;
    f.exchange(&trust, &jwt, 401).await;
    f.expect(Method::DELETE, &format!("{TRUSTS}/{trust}"), Some(OWNER), None, 200).await;
    f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 401).await;
}

#[tokio::test]
async fn remaining_mysql_transit_create_and_master_rotation_preserve_ciphertext() {
    let Some(database) = RemainingMysql::new().await else { return; };
    let f = database.fixture([7;32], true).await;
    let key = f.transit_key("remaining", "org-a", OWNER).await;
    let plain = oc::b64(b"remaining transit fixture\0payload");
    let original = f.transit(&key, "encrypt", OWNER, json!({"plaintext":plain,"context":"remaining"}), 200).await;
    assert_eq!(original["version"], 1);
    f.transit(&key, "rotate", OWNER, json!({}), 200).await;
    let latest = f.transit(&key, "encrypt", OWNER, json!({"plaintext":plain,"context":"remaining"}), 200).await;
    assert_eq!(latest["version"], 2);
    f.expect(Method::POST, "/api/instance/rotate-master", Some(OWNER), Some(json!({"new_key":oc::b64(&[9;32])})), 200).await;
    drop(f);
    let reopened = database.fixture([9;32], false).await;
    for encrypted in [&original, &latest] {
        let input = json!({"ciphertext":encrypted["ciphertext"],"context":"remaining"});
        assert_eq!(reopened.transit(&key, "decrypt", OWNER, input, 200).await["plaintext"], plain, "fresh state must decrypt every transit version after master rotation");
    }
    let denied = reopened.call(Method::POST, &format!("{KEYS}/{key}/decrypt"), Some(OWNER), Some(json!({"ciphertext":original["ciphertext"],"context":"wrong-context"}))).await;
    assert_eq!(denied.status, 400, "wrong transit context must fail authentication"); assert!(denied.body["error"].is_string()); assert!(denied.body.get("plaintext").is_none());
}

#[tokio::test]
async fn remaining_postgres_retention_policy_change_during_apply_cannot_use_stale_limit() {
    let admin_url = match std::env::var("OPENWARP_TEST_POSTGRES_URL") {
        Ok(url) => { assert!(!url.trim().is_empty(), "provided OPENWARP_TEST_POSTGRES_URL must not be empty"); url },
        Err(std::env::VarError::NotPresent) => { eprintln!("SKIP PostgreSQL policy race: OPENWARP_TEST_POSTGRES_URL is absent"); return; },
        Err(_) => panic!("OPENWARP_TEST_POSTGRES_URL must be valid Unicode"),
    };
    struct Schema { admin_url: String, name: String }
    impl Drop for Schema {
        fn drop(&mut self) {
            let url = self.admin_url.clone(); let name = self.name.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread().enable_all().build().expect("schema cleanup runtime").block_on(async move {
                    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap_or_else(|_| panic!("PostgreSQL cleanup connection failed (URL redacted)"));
                    let driver = tokio::spawn(async move { let _ = connection.await; });
                    client.batch_execute(&format!("DROP SCHEMA {name} CASCADE")).await.expect("drop only owned schema");
                    drop(client); driver.abort();
                });
            }).join().expect("owned PostgreSQL schema cleanup");
        }
    }
    let (mut blocker, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.unwrap_or_else(|_| panic!("provided PostgreSQL connection failed (URL redacted)"));
    let driver = tokio::spawn(async move { let _ = connection.await; });
    let name = format!("ow_policy_{}", oc::random_token("s").chars().take(24).collect::<String>().to_ascii_lowercase());
    blocker.batch_execute(&format!("CREATE SCHEMA {name}; SET search_path TO {name}")).await.expect("create and select private schema");
    let schema = Schema { admin_url: admin_url.clone(), name: name.clone() };
    let blocker_pid: i32 = blocker.query_one("SELECT pg_backend_pid()", &[]).await.expect("blocker PID").get(0);
    let mut url = reqwest::Url::parse(&admin_url).unwrap_or_else(|_| panic!("invalid PostgreSQL URL (redacted)"));
    let pairs: Vec<(String,String)> = url.query_pairs().map(|(k,v)| (k.into_owned(),v.into_owned())).collect();
    let options = pairs.iter().filter(|(k,_)| k == "options").map(|(_,v)| v.as_str()).collect::<Vec<_>>().join(" ");
    url.set_query(None);
    for (k,v) in pairs.iter().filter(|(k,_)| k != "options" && k != "application_name") { url.query_pairs_mut().append_pair(k,v); }
    url.query_pairs_mut().append_pair("options", format!("{options} -csearch_path={name}").trim());
    url.query_pairs_mut().append_pair("application_name", &name);
    let query = url.query().unwrap_or("").replace('+', "%20"); url.set_query(Some(&query));
    let db = Db::open(url.as_str()).await.unwrap_or_else(|_| panic!("migrate private PostgreSQL schema (URL redacted)"));
    let (live, _) = tokio::sync::broadcast::channel(16);
    let st = new_state(db, url.to_string(), "policy-race".into(), "https://openwarp.test.invalid".into(), [7;32], live,
        #[cfg(feature = "redis-cache")] None);
    let f = Fixture { app: router(st.clone()), st };
    f.sql("INSERT INTO orgs(id,name,created_at) VALUES('org-a','policy race',?)", &[json!(now())]).await;
    for (uid, token, role) in [("owner",OWNER,"owner"),("admin",ADMIN,"admin")] {
        f.sql("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,active,email_verified) VALUES(?,?,?,'','',?,1,1)", &[json!(uid),json!(format!("{uid}@test.invalid")),json!("unused-password-hash"),json!(now())]).await;
        f.sql("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(token)),json!(uid),json!(now())]).await;
        f.sql("INSERT INTO org_members(org_id,user_id,role) VALUES('org-a',?,?)", &[json!(uid),json!(role)]).await;
    }
    f.sql("INSERT INTO apps(id,org_id,name,created_at) VALUES('app-a','org-a','policy race',?)", &[json!(now())]).await;
    f.sql("INSERT INTO envs(id,app_id,name,env_key_wrapped,mode,created_at) VALUES('dev','app-a','dev',?,'sse',?)", &[json!(oc::encrypt_symmetric(&[7;32], &[11;32])),json!(now())]).await;
    remaining_retention(&f, "dev", 0).await;
    f.put("dev", json!([{"key":"TARGET","value":"policy-race-v1"}])).await;
    let sid = secret(&f.secrets("dev").await, "TARGET", "/")["id"].as_str().unwrap().to_string();
    let id = f.create_change(json!({"title":"Policy race", "changes":[{"env_id":"dev","secrets":[{"key":"TARGET","value":"policy-race-v2"}],"deletes":[]}]}), OWNER).await;
    f.change_action(&id, "approve", 1, ADMIN, 200).await;
    let before = f.secrets("dev").await; let before_history = remaining_history(&f, &sid).await;
    let lock = blocker.transaction().await.expect("blocker transaction");
    // SHARE permits preparation reads but holds apply at the secret-write transaction boundary.
    lock.batch_execute("LOCK TABLE secrets IN SHARE MODE").await.expect("hold secret writes");
    let apply_fixture = Fixture { st: f.st.clone(), app: f.app.clone() }; let apply_id = id.clone();
    let apply = tokio::spawn(async move {
        apply_fixture.call(Method::POST, &format!("/api/change-requests/{apply_id}/apply"), Some(ADMIN), Some(json!({"revision":1}))).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let waiting: bool = lock.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.application_name=$1 AND $2=ANY(pg_blocking_pids(a.pid)))", &[&name,&blocker_pid]).await.expect("observe actual apply lock wait").get(0);
            if waiting { break; }
            assert!(!apply.is_finished(), "apply must reach the lock barrier before policy mutation");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("apply reached deterministic lock barrier, not a timing guess");
    remaining_retention(&f, "dev", 1).await;
    lock.commit().await.expect("release apply after policy update committed");
    let reply = tokio::time::timeout(std::time::Duration::from_secs(20), apply).await.expect("apply finishes after barrier release").expect("apply task");
    match reply.status {
        409 => {
            assert!(reply.body["error"].is_string());
            assert_eq!(f.secrets("dev").await, before, "conflicted apply must not write secrets");
            assert_eq!(remaining_history(&f, &sid).await, before_history, "conflicted apply must not prune history");
            assert_eq!(f.change(&id).await["status"], "approved");
        },
        200 => {
            assert_eq!(f.change(&id).await["status"], "applied");
            assert_eq!(secret(&f.secrets("dev").await, "TARGET", "/")["value"], "policy-race-v2");
            let history = remaining_history(&f, &sid).await;
            assert_eq!(history.as_array().unwrap().len(), 1, "successful apply must honor the retention policy committed before its write transaction");
            assert_eq!(history[0]["version"], 2); assert_eq!(history[0]["value"], "policy-race-v2");
        },
        status => panic!("policy race must conflict atomically or apply with current retention, got {status}"),
    }
    drop(f); drop(blocker); driver.abort(); drop(schema);
}
