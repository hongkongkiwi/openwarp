use axum::{body::{to_bytes, Body}, http::Request};
use openwarp_crypto as oc;
use openwarp_server::{db::{self, Db}, new_state, router, PeerAddr, S};
use serde_json::{json, Value};
use tower::ServiceExt;

const ISSUER: &str = "https://rekey-review.test.invalid";
struct Account { id: String, email: String, token: String, keys: oc::Keypair }
impl Account {
    fn new(id: &str) -> Self { Self { id: id.into(), email: format!("{id}@rekey-review.test.invalid"), token: oc::random_token("session"), keys: oc::Keypair::generate() } }
}
struct Reply { status: u16, body: Value }
struct Fixture { state: S, owner: Account, member: Account, nonholder: Account, env: String, key: [u8;32] }
impl Fixture {
    async fn new(delegated: bool) -> Self {
        let db = Db::open_memory().await.unwrap(); let t = openwarp_server::clock::now();
        let owner = Account::new("owner"); let member = Account::new("member"); let nonholder = Account::new("nonholder");
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES('org','review',?)", &[json!(t)]).await.unwrap();
        for (a, role) in [(&owner,"owner"),(&member,"developer"),(&nonholder,"developer")] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,1)",
                &[json!(a.id),json!(a.email),json!("unused"),json!(a.keys.public),json!("unused"),json!(t)]).await.unwrap();
            db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES('org',?,?)", &[json!(a.id),json!(role)]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&a.token)),json!(a.id),json!(t)]).await.unwrap();
        }
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES('app','org','review',?)", &[json!(t)]).await.unwrap();
        let (live, _) = tokio::sync::broadcast::channel(16);
        let state = new_state(db, "sqlite::memory:".into(), "client-rekey-review".into(), ISSUER.into(), [7;32], live, #[cfg(feature="redis-cache")] None);
        let mut f = Self { state, owner, member, nonholder, env: String::new(), key: oc::random_key() };
        let wrapped = oc::encrypt_to(&f.owner.keys.public,&f.key).unwrap();
        let created = if delegated {
            let runner = oc::Keypair::generate();
            let r = f.call("POST","/api/orgs/org/runners",&f.owner.token,Some(json!({"name":"review-runner","public_key":runner.public}))).await;
            assert_eq!(r.status,200,"runner fixture");
            f.call("POST","/api/apps/app/envs",&f.owner.token,Some(json!({"name":"vault","mode":"delegated","runner_id":r.body["id"],"wrapped_key":wrapped,"runner_wrapped_key":oc::encrypt_to(&runner.public,&f.key).unwrap()}))).await
        } else {
            f.call("POST","/api/apps/app/envs/e2e",&f.owner.token,Some(json!({"name":"vault","wrapped_key":wrapped}))).await
        };
        assert_eq!(created.status,200,"client-held environment fixture"); f.env = created.body["id"].as_str().unwrap().into();
        let meta = f.meta().await;
        let r = f.call("PUT",&f.path("e2e/secrets"),&f.owner.token,Some(f.write(&f.key,&meta["key_generation"],"original"))).await;
        assert_eq!(r.status,200,"session ciphertext write positive control"); assert_eq!(r.body["deployed"],1);
        let data = f.read().await;
        assert_eq!(f.owner.keys.decrypt(data["wrapped_key"].as_str().unwrap()).unwrap(),f.key);
        assert_eq!(oc::decrypt_symmetric(&f.key,data["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(),b"original");
        f
    }
    fn path(&self, suffix: &str) -> String { format!("/api/envs/{}/{}",self.env,suffix) }
    async fn call(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Reply {
        let mut req = Request::builder().method(method).uri(path).header("authorization",format!("Bearer {token}"))
            .extension(PeerAddr(std::net::IpAddr::from([127,0,0,1])));
        let body = match body { Some(v) => { req = req.header("content-type","application/json"); Body::from(v.to_string()) }, None => Body::empty() };
        let response = router(self.state.clone()).oneshot(req.body(body).unwrap()).await.unwrap(); let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(),1024*1024).await.unwrap();
        Reply { status, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
    }
    async fn meta(&self) -> Value { let r = self.call("GET",&self.path("e2e/meta"),&self.owner.token,None).await; assert_eq!(r.status,200,"session holder metadata positive control"); r.body }
    async fn read(&self) -> Value { let r = self.call("GET",&self.path("e2e/secrets"),&self.owner.token,None).await; assert_eq!(r.status,200,"session holder ciphertext positive control"); r.body }
    fn write(&self, key: &[u8;32], generation: &Value, value: &str) -> Value {
        json!({"expected_generation":generation,"secrets":[{"key_hash":oc::hash_token("/:API_KEY"),"key_enc":oc::encrypt_symmetric(key,b"API_KEY"),"value_enc":oc::encrypt_symmetric(key,value.as_bytes()),"path_enc":oc::encrypt_symmetric(key,b"/")}]})
    }
    fn grant_body(&self, account: &Account, key: &[u8;32], generation: &Value) -> Value { json!({"expected_generation":generation,"email":account.email,"wrapped_key":oc::encrypt_to(&account.keys.public,key).unwrap()}) }
    async fn grant_member(&self) {
        let meta = self.meta().await;
        let r = self.call("POST",&self.path("e2e/grant"),&self.owner.token,Some(self.grant_body(&self.member,&self.key,&meta["key_generation"]))).await;
        assert_eq!(r.status,200,"session grant positive control");
        let r = self.call("GET",&self.path("e2e/secrets"),&self.member.token,None).await; assert_eq!(r.status,200);
        assert_eq!(self.member.keys.decrypt(r.body["wrapped_key"].as_str().unwrap()).unwrap(),self.key);
    }
    async fn pending(&self) {
        self.grant_member().await;
        let r = self.call("DELETE",&self.path("e2e/grants/member"),&self.owner.token,None).await;
        assert_eq!(r.status,200,"revocation fixture"); assert_eq!(self.meta().await["rekey_required"],true);
        assert_eq!(self.call("GET",&self.path("e2e/secrets"),&self.member.token,None).await.status,403,"revoked fixture is not a holder");
    }
    async fn stored(&self) -> Value {
        let db = self.state.db();
        let mut out = serde_json::Map::new();
        for (name,sql) in [
            ("ciphertexts","SELECT * FROM secrets WHERE env_id=? ORDER BY id"),
            ("versions","SELECT v.* FROM secret_versions v JOIN secrets s ON s.id=v.secret_id WHERE s.env_id=? ORDER BY v.id"),
            ("grants","SELECT * FROM env_keys WHERE env_id=? ORDER BY user_id"),
            ("runner_grants","SELECT * FROM runner_env_keys WHERE env_id=? ORDER BY runner_id"),
            ("environment","SELECT * FROM envs WHERE id=?"),
            ("audit","SELECT * FROM audit WHERE env_id=? ORDER BY seq"),
        ] { out.insert(name.into(),json!(db.query(sql,&[json!(self.env)]).await.unwrap().iter().map(db::obj).collect::<Vec<_>>())); }
        Value::Object(out)
    }
    async fn oauth(&self, account: &Account, scope: &str, audience: &str, kind: &str, expires: i64) -> String {
        let registered = self.call("POST","/oauth/register",&account.token,Some(json!({"client_name":"openwarp-cli","redirect_uris":["http://127.0.0.1:8917/callback"],"token_endpoint_auth_method":"none","scope":"secrets:read secrets:write"}))).await;
        assert_eq!(registered.status,201,"CLI OAuth client registration fixture");
        let token = oc::random_token("owat"); let t = openwarp_server::clock::now();
        self.state.db().exec("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,kind,pair_id,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            &[json!(oc::hash_token(&token)),registered.body["client_id"].clone(),json!(account.id),json!(scope),json!(audience),json!(kind),json!(oc::random_token("pair")),json!(expires),json!(t)]).await.unwrap();
        token
    }
    async fn rotate(&self) -> [u8;32] {
        let meta = self.meta().await; let data = self.read().await; let key = oc::random_key();
        let secrets = data["secrets"].as_array().unwrap().iter().map(|s| {
            let mut rotated = s.clone();
            for field in ["key_enc","value_enc","path_enc"] { rotated[field] = json!(oc::encrypt_symmetric(&key,&oc::decrypt_symmetric(&self.key,s[field].as_str().unwrap()).unwrap())); }
            rotated
        }).collect::<Vec<_>>();
        let grants = [&self.owner,&self.member].iter().map(|a|json!({"user_id":a.id,"wrapped_key":oc::encrypt_to(&a.keys.public,&key).unwrap()})).collect::<Vec<_>>();
        let body = json!({"expected_generation":meta["key_generation"],"membership_version":meta["membership_version"],"snapshot_token":meta["snapshot_token"],"secrets":secrets,"grants":grants});
        assert_eq!(self.call("POST",&self.path("e2e/rekey"),&self.owner.token,Some(body)).await.status,200,"session client rekey positive control");
        key
    }
}
fn status(failures: &mut Vec<String>, context: &str, actual: u16, allowed: &[u16]) {
    if !allowed.contains(&actual) { failures.push(format!("{context}: expected {allowed:?}, got {actual}")); }
}
fn unchanged(failures: &mut Vec<String>, context: &str, before: &Value, after: &Value) {
    for field in ["ciphertexts","versions","grants","runner_grants","environment","audit"] {
        if before[field] != after[field] { failures.push(format!("{context}: persisted {field} changed")); }
    }
}

#[tokio::test]
async fn pending_client_pitr_rejects_owner_revoked_and_nonholder_without_mutation() {
    let mut failures = Vec::new();
    for delegated in [false,true] { for actor in ["owner","revoked","nonholder"] { for historical in [true,false] {
        let f = Fixture::new(delegated).await; f.pending().await;
        let token = match actor { "owner"=>&f.owner.token,"revoked"=>&f.member.token,_=>&f.nonholder.token };
        let before = f.stored().await; let meta = f.meta().await;
        let ts = if historical {0} else {openwarp_server::clock::now()};
        let context = format!("{} pending {actor} PITR timestamp {}",if delegated {"delegated"} else {"e2e"},if historical {"0"} else {"now"});
        let r = f.call("POST",&f.path("restore-point"),token,Some(json!({"timestamp":ts}))).await;
        status(&mut failures,&context,r.status,&[403,409]); unchanged(&mut failures,&context,&before,&f.stored().await);
        if f.meta().await != meta { failures.push(format!("{context}: holder metadata changed")); }
    } } }
    assert!(failures.is_empty(),"{}",failures.join("\n"));
}

#[tokio::test]
async fn nonpending_client_pitr_requires_an_unimplemented_client_restore_protocol() {
    let mut failures = Vec::new();
    for delegated in [false,true] { for historical in [true,false] {
        let f = Fixture::new(delegated).await; assert_eq!(f.meta().await["rekey_required"],false);
        let before = f.stored().await; let ts = if historical {0} else {openwarp_server::clock::now()};
        let context = format!("{} nonpending PITR timestamp {}",if delegated {"delegated"} else {"e2e"},if historical {"0"} else {"now"});
        let r = f.call("POST",&f.path("restore-point"),&f.owner.token,Some(json!({"timestamp":ts}))).await;
        status(&mut failures,&context,r.status,&[409]); unchanged(&mut failures,&context,&before,&f.stored().await);
    } }
    assert!(failures.is_empty(),"{}",failures.join("\n"));
}

#[tokio::test]
async fn live_cli_oauth_holder_can_read_write_and_grant_with_generation_fencing() {
    let f = Fixture::new(false).await; let mut failures = Vec::new();
    let token = f.oauth(&f.owner,"secrets:read secrets:write",ISSUER,"access",openwarp_server::clock::now()+3600).await;
    assert_eq!(f.call("GET","/api/me",&token,None).await.status,200,"live OAuth must already authenticate as the same account outside client rekey");
    let cached = f.meta().await; let original = f.read().await;
    let r = f.call("GET",&f.path("e2e/meta"),&token,None).await; status(&mut failures,"live OAuth holder metadata",r.status,&[200]);
    if r.status==200 && r.body!=cached { failures.push("OAuth and session holder metadata differ".into()); }
    let r = f.call("GET",&f.path("e2e/secrets"),&token,None).await; status(&mut failures,"live OAuth holder ciphertext",r.status,&[200]);
    if r.status==200 && r.body!=original { failures.push("OAuth and session holder ciphertext differ".into()); }
    let r = f.call("PUT",&f.path("e2e/secrets"),&token,Some(f.write(&f.key,&cached["key_generation"],"oauth-write"))).await;
    status(&mut failures,"live OAuth current-generation write",r.status,&[200]);
    if r.status==200 {
        assert_eq!(r.body["deployed"],1);
        assert_eq!(oc::decrypt_symmetric(&f.key,f.read().await["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(),b"oauth-write");
    }
    let r = f.call("POST",&f.path("e2e/grant"),&token,Some(f.grant_body(&f.member,&f.key,&cached["key_generation"]))).await;
    status(&mut failures,"live OAuth current-generation grant",r.status,&[200]);
    if r.status==200 {
        let member = f.call("GET",&f.path("e2e/secrets"),&f.member.token,None).await; assert_eq!(member.status,200);
        assert_eq!(f.member.keys.decrypt(member.body["wrapped_key"].as_str().unwrap()).unwrap(),f.key);
    }
    f.grant_member().await; let key = f.rotate().await; let current = f.meta().await;
    assert_eq!(current["key_generation"].as_u64().unwrap(),cached["key_generation"].as_u64().unwrap()+1);
    let before = f.stored().await;
    let r = f.call("PUT",&f.path("e2e/secrets"),&token,Some(f.write(&f.key,&cached["key_generation"],"stale"))).await;
    status(&mut failures,"live OAuth stale-generation write",r.status,&[409]); unchanged(&mut failures,"stale OAuth write",&before,&f.stored().await);
    let r = f.call("POST",&f.path("e2e/grant"),&token,Some(f.grant_body(&f.nonholder,&f.key,&cached["key_generation"]))).await;
    status(&mut failures,"live OAuth stale-generation grant",r.status,&[409]); unchanged(&mut failures,"stale OAuth grant",&before,&f.stored().await);
    let r = f.call("PUT",&f.path("e2e/secrets"),&token,Some(f.write(&key,&current["key_generation"],"refreshed"))).await;
    status(&mut failures,"live OAuth refreshed-generation write",r.status,&[200]);
    let r = f.call("POST",&f.path("e2e/grant"),&token,Some(f.grant_body(&f.nonholder,&key,&current["key_generation"]))).await;
    status(&mut failures,"live OAuth refreshed-generation grant",r.status,&[200]);
    if r.status==200 {
        let data = f.call("GET",&f.path("e2e/secrets"),&f.nonholder.token,None).await; assert_eq!(data.status,200);
        assert_eq!(f.nonholder.keys.decrypt(data.body["wrapped_key"].as_str().unwrap()).unwrap(),key);
        assert_eq!(oc::decrypt_symmetric(&key,data.body["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(),b"refreshed");
    }
    assert!(failures.is_empty(),"{}",failures.join("\n"));
}

#[tokio::test]
async fn client_routes_keep_oauth_liveness_scope_membership_and_credential_class_boundaries() {
    let f = Fixture::new(false).await; let t = openwarp_server::clock::now(); let meta = f.meta().await;
    let live = f.oauth(&f.owner,"secrets:read secrets:write",ISSUER,"access",t+3600).await;
    let expired = f.oauth(&f.owner,"secrets:read secrets:write",ISSUER,"access",t-1).await;
    let revoked = f.oauth(&f.owner,"secrets:read secrets:write",ISSUER,"access",t+3600).await;
    f.state.db().exec("DELETE FROM oauth_tokens WHERE token_hash=?",&[json!(oc::hash_token(&revoked))]).await.unwrap();
    let refresh = f.oauth(&f.owner,"secrets:read secrets:write",ISSUER,"refresh",t+3600).await;
    let wrong_audience = f.oauth(&f.owner,"secrets:read secrets:write",&format!("{ISSUER}/mcp"),"access",t+3600).await;
    let nonholder = f.oauth(&f.nonholder,"secrets:read secrets:write",ISSUER,"access",t+3600).await;
    let no_scope = f.oauth(&f.owner,"",ISSUER,"access",t+3600).await;
    let read_only = f.oauth(&f.owner,"secrets:read",ISSUER,"access",t+3600).await;
    let mut credentials = vec![("expired OAuth",expired),("revoked OAuth",revoked),("refresh credential",refresh),("wrong OAuth audience",wrong_audience),("OAuth nonholder",nonholder),("OAuth no scopes",no_scope)];
    for (name,kind,env,uid) in [("service credential","human",f.env.as_str(),f.owner.id.as_str()),("wrong-environment service","human","another-environment",f.owner.id.as_str()),("machine credential","machine",f.env.as_str(),"machine")] {
        if kind=="machine" { f.state.db().exec("INSERT INTO identities(id,org_id,name,role,created_at) VALUES('machine','org','review-machine','owner',?)",&[json!(t)]).await.unwrap(); }
        let token = oc::random_token("owt");
        f.state.db().exec("INSERT INTO tokens(id,org_id,app_id,env_id,name,token_hash,created_by,kind,scopes,created_at) VALUES(?,'org','app',?,?,?,?,?,'secrets:read secrets:write',?)",
            &[json!(oc::random_token("token")),json!(env),json!(name),json!(oc::hash_token(&token)),json!(uid),json!(kind),json!(t)]).await.unwrap();
        if name!="wrong-environment service" { assert_eq!(f.call("GET",&f.path("meta"),&token,None).await.status,200,"{name} authentication positive control"); }
        credentials.push((name,token));
    }
    let broker = oc::random_token("owb");
    f.state.db().exec("INSERT INTO broker_sessions(id,token_hash,org_id,app_id,service_id,revision,subject_user_id,issuer_user_id,capabilities,approvals,expires_at,created_at) VALUES('broker',?,'org','app','service',1,'owner','owner','[]','[]',?,?)",
        &[json!(oc::hash_token(&broker)),json!(t+3600),json!(t)]).await.unwrap(); credentials.push(("broker credential",broker));
    let mut failures = Vec::new();
    for (name,token) in credentials {
        let before = f.stored().await;
        for (method,suffix,body) in [("GET","e2e/meta",None),("GET","e2e/secrets",None),("PUT","e2e/secrets",Some(f.write(&f.key,&meta["key_generation"],"denied"))),("POST","e2e/grant",Some(f.grant_body(&f.member,&f.key,&meta["key_generation"])))] {
            let r = f.call(method,&f.path(suffix),&token,body).await; status(&mut failures,&format!("{name} {method} {suffix}"),r.status,&[401,403]);
            unchanged(&mut failures,name,&before,&f.stored().await);
        }
    }
    let before = f.stored().await;
    for (method,suffix,body) in [("PUT","e2e/secrets",f.write(&f.key,&meta["key_generation"],"read-only")),("POST","e2e/grant",f.grant_body(&f.member,&f.key,&meta["key_generation"]))] {
        status(&mut failures,"read-only OAuth cannot mutate",f.call(method,&f.path(suffix),&read_only,Some(body)).await.status,&[403]); unchanged(&mut failures,"read-only OAuth",&before,&f.stored().await);
    }
    f.state.db().exec("DELETE FROM org_members WHERE org_id='org' AND user_id='owner'",&[]).await.unwrap();
    for (method,suffix,body) in [("GET","e2e/meta",None),("GET","e2e/secrets",None),("PUT","e2e/secrets",Some(f.write(&f.key,&meta["key_generation"],"removed-member"))),("POST","e2e/grant",Some(f.grant_body(&f.member,&f.key,&meta["key_generation"])))] {
        status(&mut failures,"live OAuth removed member",f.call(method,&f.path(suffix),&live,body).await.status,&[403]); unchanged(&mut failures,"removed membership",&before,&f.stored().await);
    }
    assert!(failures.is_empty(),"{}",failures.join("\n"));
}
