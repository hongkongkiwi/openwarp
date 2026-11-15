use axum::{body::{to_bytes, Body}, http::Request};
use openwarp_crypto as oc;
use openwarp_server::{db::Db, new_state, router, PeerAddr, S};
use serde_json::{json, Value};
use tower::ServiceExt;

struct Account { id: String, email: String, token: String, keys: oc::Keypair }
impl Account {
    fn new(name: &str) -> Self {
        Self { id: name.into(), email: format!("{name}@rekey.test.invalid"), token: oc::random_token("session"), keys: oc::Keypair::generate() }
    }
}
struct Reply { status: u16, body: Value }
struct Fixture { state: S, owner: Account, member: Account, env: String, key: [u8;32], runner: Option<(String, String, oc::Keypair)> }
fn state(db: Db) -> S {
    let (live, _) = tokio::sync::broadcast::channel(16);
    new_state(db, "sqlite::memory:".into(), "client-rekey-tests".into(), "https://rekey.test.invalid".into(), [7;32], live, #[cfg(feature="redis-cache")] None)
}
impl Fixture {
    async fn new(delegated: bool, populated: bool) -> Self { Self::with_db(Db::open_memory().await.unwrap(), delegated, populated).await }
    async fn with_db(db: Db, delegated: bool, populated: bool) -> Self {
        let owner = Account::new("owner"); let member = Account::new("member");
        let t = openwarp_server::clock::now();
        db.exec("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", &[json!("org"),json!("rekey"),json!(t)]).await.unwrap();
        for (account, role) in [(&owner, "owner"), (&member, "developer")] {
            db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at,email_verified) VALUES(?,?,?,?,?,?,?)",
                &[json!(account.id),json!(account.email),json!("unused"),json!(account.keys.public),json!("unused"),json!(t),json!(1)]).await.unwrap();
            db.exec("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)", &[json!("org"),json!(account.id),json!(role)]).await.unwrap();
            db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)", &[json!(oc::hash_token(&account.token)),json!(account.id),json!(t)]).await.unwrap();
        }
        db.exec("INSERT INTO apps(id,org_id,name,created_at) VALUES(?,?,?,?)", &[json!("app"),json!("org"),json!("rekey"),json!(t)]).await.unwrap();
        let mut f = Self { state: state(db), owner, member, env: String::new(), key: oc::random_key(), runner: None };
        let wrapped = oc::encrypt_to(&f.owner.keys.public, &f.key).unwrap();
        let created = if delegated {
            let keys = oc::Keypair::generate();
            let r = f.call("POST", "/api/orgs/org/runners", &f.owner.token, Some(json!({"name":"customer-runner","public_key":keys.public}))).await;
            assert_eq!(r.status, 200, "runner fixture must be created: {}", r.body);
            let id = r.body["id"].as_str().unwrap().to_string(); let token = r.body["token"].as_str().unwrap().to_string();
            let body = json!({"name":"vault","mode":"delegated","runner_id":id,"wrapped_key":wrapped,"runner_wrapped_key":oc::encrypt_to(&keys.public,&f.key).unwrap()});
            f.runner = Some((id, token, keys));
            f.call("POST", "/api/apps/app/envs", &f.owner.token, Some(body)).await
        } else {
            f.call("POST", "/api/apps/app/envs/e2e", &f.owner.token, Some(json!({"name":"vault","wrapped_key":wrapped}))).await
        };
        assert_eq!(created.status, 200, "client-created environment fixture: {}", created.body);
        f.env = created.body["id"].as_str().unwrap().into();
        if populated { f.put(&f.key, "original").await; }
        let data = f.read(&f.owner).await;
        assert_eq!(f.unwrap(&f.owner, &data), f.key, "fixture key must unwrap entirely on the client");
        f
    }
    fn path(&self, suffix: &str) -> String { format!("/api/envs/{}/{}", self.env, suffix) }
    async fn call(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Reply {
        let mut request = Request::builder().method(method).uri(path).header("authorization", format!("Bearer {token}"))
            .extension(PeerAddr(std::net::IpAddr::from([127,0,0,1])));
        let body = match body { Some(v) => { request = request.header("content-type", "application/json"); Body::from(v.to_string()) }, None => Body::empty() };
        let response = router(self.state.clone()).oneshot(request.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024*1024).await.unwrap();
        Reply { status, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
    }
    async fn meta(&self) -> Value {
        let r = self.call("GET", &self.path("e2e/meta"), &self.owner.token, None).await;
        assert_eq!(r.status, 200, "holder metadata must remain readable: {}", r.body);
        r.body
    }
    async fn snapshot(&self) -> Value {
        let meta = self.meta().await;
        assert!(meta["key_generation"].as_u64().is_some_and(|n| n >= 1), "metadata must expose a positive key_generation");
        assert!(meta["membership_version"].as_u64().is_some(), "metadata must expose membership_version");
        assert!(meta["snapshot_token"].as_str().is_some_and(|s| !s.is_empty()), "metadata must expose a nonempty opaque snapshot_token");
        assert!(meta["rekey_required"].is_boolean(), "metadata must expose the pending state");
        meta
    }
    async fn read(&self, account: &Account) -> Value {
        let r = self.call("GET", &self.path("e2e/secrets"), &account.token, None).await;
        assert_eq!(r.status, 200, "authorized holder needs ciphertext and its wrapped key: {}", r.body);
        r.body
    }
    fn unwrap(&self, account: &Account, data: &Value) -> [u8;32] {
        account.keys.decrypt(data["wrapped_key"].as_str().unwrap()).unwrap().try_into().unwrap()
    }
    fn ciphertext(key: &[u8;32], value: &str) -> Value {
        json!({"key_hash":oc::hash_token("/:API_KEY"),"key_enc":oc::encrypt_symmetric(key,b"API_KEY"),"value_enc":oc::encrypt_symmetric(key,value.as_bytes()),"path_enc":oc::encrypt_symmetric(key,b"/")})
    }
    async fn put(&self, key: &[u8;32], value: &str) {
        let meta = self.meta().await;
        let r = self.call("PUT", &self.path("e2e/secrets"), &self.owner.token, Some(json!({"expected_generation":meta["key_generation"],"secrets":[Self::ciphertext(key,value)]}))).await;
        assert_eq!(r.status, 200, "ordinary client ciphertext write: {}", r.body);
        assert_eq!(r.body["deployed"], 1);
    }
    async fn grant(&self) {
        let meta = self.meta().await;
        let r = self.call("POST", &self.path("e2e/grant"), &self.owner.token, Some(json!({"expected_generation":meta["key_generation"],"email":self.member.email,"wrapped_key":oc::encrypt_to(&self.member.keys.public,&self.key).unwrap()}))).await;
        assert_eq!(r.status, 200, "grant fixture: {}", r.body);
        assert_eq!(self.unwrap(&self.member, &self.read(&self.member).await), self.key);
    }
    async fn revoke(&self) {
        let r = self.call("DELETE", &self.path(&format!("e2e/grants/{}",self.member.id)), &self.owner.token, None).await;
        assert_eq!(r.status, 200, "revocation must succeed without an online grantee: {}", r.body);
        assert_eq!(r.body["rekey_required"], true);
    }
    fn payload(&self, meta: &Value, data: &Value, holder: &Account, recipients: &[&Account]) -> (Value, [u8;32]) {
        let old = self.unwrap(holder, data); let new = oc::random_key();
        let secrets: Vec<Value> = data["secrets"].as_array().unwrap().iter().map(|s| {
            let mut rotated = s.clone();
            for field in ["key_enc", "value_enc", "path_enc"] {
                let plain = oc::decrypt_symmetric(&old, s[field].as_str().unwrap()).unwrap();
                rotated[field] = json!(oc::encrypt_symmetric(&new, &plain));
            }
            rotated
        }).collect();
        let grants: Vec<Value> = recipients.iter().map(|a| json!({"user_id":a.id,"wrapped_key":oc::encrypt_to(&a.keys.public,&new).unwrap()})).collect();
        (json!({"expected_generation":meta["key_generation"],"membership_version":meta["membership_version"],"snapshot_token":meta["snapshot_token"],"secrets":secrets,"grants":grants}), new)
    }
    async fn commit(&self, token: &str, payload: Value) -> Reply { self.call("POST", &self.path("e2e/rekey"), token, Some(payload)).await }
    async fn audit(&self) -> Vec<Value> {
        let r = self.call("GET", "/api/orgs/org/audit", &self.owner.token, None).await;
        assert_eq!(r.status, 200); let mut rows = r.body.as_array().unwrap().clone();
        rows.sort_by_key(|r| r["seq"].as_i64().unwrap()); rows
    }
    async fn assert_rotated(&self, before: &Value, key: &[u8;32], account: &Account) {
        let after = self.read(account).await;
        assert_eq!(self.unwrap(account,&after), *key);
        let previous = before["secrets"].as_array().unwrap(); let current = after["secrets"].as_array().unwrap();
        assert_eq!(current.len(), previous.len());
        for old in previous {
            let new = current.iter().find(|s| s["id"] == old["id"]).unwrap();
            assert_eq!(new["version"].as_i64().unwrap(), old["version"].as_i64().unwrap()+1);
            for field in ["key_enc", "value_enc", "path_enc"] {
                assert_ne!(new[field], old[field]);
                assert!(oc::decrypt_symmetric(&self.key,new[field].as_str().unwrap()).is_err(), "old environment key must not decrypt rotated ciphertext");
            }
            assert_eq!(oc::decrypt_symmetric(key,new["key_enc"].as_str().unwrap()).unwrap(), b"API_KEY");
            assert_eq!(oc::decrypt_symmetric(key,new["value_enc"].as_str().unwrap()).unwrap(), b"original");
            assert_eq!(oc::decrypt_symmetric(key,new["path_enc"].as_str().unwrap()).unwrap(), b"/");
        }
    }
}
fn invalid(r: &Reply, context: &str) { assert!(matches!(r.status,400|409), "{context} must fail validation without committing, got {} {}",r.status,r.body); }

#[tokio::test]
async fn metadata_starts_at_generation_one_and_empty_environment_can_rotate() {
    let f = Fixture::new(false,false).await;
    let meta = f.snapshot().await;
    assert_eq!(meta["key_generation"],1); assert_eq!(meta["rekey_required"],false); assert_eq!(meta["mode"],"e2e");
    let data = f.read(&f.owner).await; assert!(data["secrets"].as_array().unwrap().is_empty());
    let (payload,key) = f.payload(&meta,&data,&f.owner,&[&f.owner]);
    let r = f.commit(&f.owner.token,payload).await;
    assert_eq!(r.status,200,"an empty environment still needs key rotation: {}",r.body); assert_eq!(r.body["rekeyed"],0);
    let after = f.snapshot().await; assert_eq!(after["key_generation"],2); assert_eq!(after["rekey_required"],false);
    f.assert_rotated(&data,&key,&f.owner).await;
}

#[tokio::test]
async fn rekey_requires_each_server_snapshot_precondition_and_rejects_tampering() {
    let f = Fixture::new(false,true).await; let meta = f.snapshot().await; let data = f.read(&f.owner).await;
    let (payload,_) = f.payload(&meta,&data,&f.owner,&[&f.owner]); let audit = f.audit().await;
    for field in ["expected_generation","membership_version","snapshot_token"] {
        let mut missing = payload.clone(); missing.as_object_mut().unwrap().remove(field);
        invalid(&f.commit(&f.owner.token,missing).await,&format!("missing {field}"));
        assert_eq!(f.read(&f.owner).await,data); assert_eq!(f.audit().await,audit);
    }
    let mut tampered = payload.clone(); tampered["snapshot_token"] = json!(format!("{}x",meta["snapshot_token"].as_str().unwrap()));
    invalid(&f.commit(&f.owner.token,tampered).await,"modified snapshot token");
    let other = f.call("POST","/api/apps/app/envs/e2e",&f.owner.token,Some(json!({"name":"other","wrapped_key":oc::encrypt_to(&f.owner.keys.public,&f.key).unwrap()}))).await;
    assert_eq!(other.status,200); let other_id = other.body["id"].as_str().unwrap();
    let foreign = f.call("GET",&format!("/api/envs/{other_id}/e2e/meta"),&f.owner.token,None).await; assert_eq!(foreign.status,200);
    let mut cross_env = payload; cross_env["snapshot_token"] = foreign.body["snapshot_token"].clone();
    invalid(&f.commit(&f.owner.token,cross_env).await,"snapshot from another environment");
    assert_eq!(f.read(&f.owner).await,data); assert_eq!(f.snapshot().await["key_generation"],meta["key_generation"]);
}

#[tokio::test]
async fn grants_and_revocations_advance_membership_and_fence_older_snapshots() {
    let f = Fixture::new(false,true).await; let first = f.snapshot().await; let data = f.read(&f.owner).await;
    let (stale,_) = f.payload(&first,&data,&f.owner,&[&f.owner]);
    f.grant().await; let granted = f.snapshot().await;
    assert_eq!(granted["membership_version"].as_u64().unwrap(),first["membership_version"].as_u64().unwrap()+1);
    assert_eq!(granted["key_generation"],first["key_generation"]);
    let mut stale = stale; stale["grants"].as_array_mut().unwrap().push(json!({"user_id":f.member.id,"wrapped_key":oc::encrypt_to(&f.member.keys.public,&oc::random_key()).unwrap()}));
    assert_eq!(f.commit(&f.owner.token,stale).await.status,409,"a new grant invalidates an in-progress rekey");
    let (mut stale,_) = f.payload(&granted,&data,&f.owner,&[&f.owner]);
    f.revoke().await; let revoked = f.snapshot().await;
    assert_eq!(revoked["membership_version"].as_u64().unwrap(),granted["membership_version"].as_u64().unwrap()+1);
    assert_eq!(revoked["key_generation"],first["key_generation"]); assert_eq!(revoked["rekey_required"],true);
    stale["membership_version"] = revoked["membership_version"].clone();
    assert_eq!(f.commit(&f.owner.token,stale).await.status,409,"a current membership number cannot repair an old snapshot token");
    assert_eq!(f.read(&f.owner).await,data);
}

#[tokio::test]
async fn offline_revocation_survives_state_recreation_and_holder_finishes_locally() {
    let dir = std::env::temp_dir().join(format!("openwarp-client-rekey-{}",oc::random_token("fixture")));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf); impl Drop for Cleanup { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    let _cleanup = Cleanup(dir.clone()); let url = format!("sqlite://{}",dir.join("private.db").display());
    let mut f = Fixture::with_db(Db::open(&url).await.unwrap(),false,true).await;
    f.grant().await; let before = f.read(&f.owner).await; f.revoke().await;
    f.state = state(Db::open(&url).await.unwrap());
    let pending = f.snapshot().await; assert_eq!(pending["rekey_required"],true,"pending state must not be process-local");
    assert_eq!(f.read(&f.owner).await,before,"retained holder can fetch the old key and ciphertext for local rekey");
    let grants = f.call("GET",&f.path("e2e/grants"),&f.owner.token,None).await; assert_eq!(grants.status,200);
    assert_eq!(grants.body.as_array().unwrap().len(),1); assert_eq!(grants.body[0]["user_id"],f.owner.id);
    assert_eq!(f.call("GET",&f.path("e2e/secrets"),&f.member.token,None).await.status,403,"revoked holder cannot fetch even old ciphertext");
    let blocked = f.call("PUT",&f.path("e2e/secrets"),&f.owner.token,Some(json!({"expected_generation":pending["key_generation"],"secrets":[Fixture::ciphertext(&f.key,"must-not-land")]}))).await;
    assert_eq!(blocked.status,409,"ordinary writes must stop until rotation finishes: {}",blocked.body);
    assert_eq!(f.call("GET",&f.path("export"),&f.owner.token,None).await.status,409,"pending export must be denied before a plaintext workflow or step-up");
    assert_eq!(f.read(&f.owner).await,before);
    let (payload,key) = f.payload(&pending,&before,&f.owner,&[&f.owner]); let r = f.commit(&f.owner.token,payload).await;
    assert_eq!(r.status,200,"an online retained holder can finish later: {}",r.body);
    let after = f.snapshot().await; assert_eq!(after["rekey_required"],false); assert_eq!(after["key_generation"].as_u64().unwrap(),pending["key_generation"].as_u64().unwrap()+1);
    f.assert_rotated(&before,&key,&f.owner).await; f.put(&key,"resumed").await;
    assert_eq!(f.call("GET",&f.path("e2e/secrets"),&f.member.token,None).await.status,403);
}

#[tokio::test]
async fn changed_secret_versions_invalidate_snapshot_without_membership_change() {
    let f = Fixture::new(false,true).await; let meta = f.snapshot().await; let before = f.read(&f.owner).await;
    let (stale,_) = f.payload(&meta,&before,&f.owner,&[&f.owner]);
    f.put(&f.key,"concurrent-edit").await; let edited = f.read(&f.owner).await; let current = f.snapshot().await; let audit = f.audit().await;
    assert_eq!(current["key_generation"],meta["key_generation"]); assert_eq!(current["membership_version"],meta["membership_version"]);
    assert_eq!(edited["secrets"][0]["version"].as_i64().unwrap(),before["secrets"][0]["version"].as_i64().unwrap()+1);
    let r = f.commit(&f.owner.token,stale).await;
    assert_eq!(r.status,409,"a stale snapshot must not overwrite a newer ciphertext: {}",r.body);
    assert_eq!(f.read(&f.owner).await,edited); assert_eq!(f.audit().await,audit);
    let (payload,key) = f.payload(&current,&edited,&f.owner,&[&f.owner]); let r = f.commit(&f.owner.token,payload).await;
    assert_eq!(r.status,200,"refreshing the snapshot permits a retry: {}",r.body);
    let after = f.read(&f.owner).await;
    assert_eq!(oc::decrypt_symmetric(&key,after["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(),b"concurrent-edit");
}

#[tokio::test]
async fn rekey_requires_a_current_member_holder_account_not_automation_or_removed_holder() {
    let f = Fixture::new(false,true).await; let meta = f.snapshot().await; let before = f.read(&f.owner).await;
    let (payload,_) = f.payload(&meta,&before,&f.owner,&[&f.owner]);
    let nonholder = f.commit(&f.member.token,payload).await; assert_eq!(nonholder.status,403,"workspace membership alone is not key custody");
    f.grant().await; let meta = f.snapshot().await; let data = f.read(&f.member).await;
    let (removed_payload,_) = f.payload(&meta,&data,&f.member,&[&f.owner,&f.member]);
    let token = f.call("POST","/api/apps/app/tokens",&f.owner.token,Some(json!({"name":"not-an-account","env_id":f.env,"scopes":"secrets:read secrets:write"}))).await;
    assert_eq!(token.status,200,"service token positive control: {}",token.body);
    let (payload,_) = f.payload(&meta,&before,&f.owner,&[&f.owner,&f.member]);
    let automation = f.commit(token.body["token"].as_str().unwrap(),payload).await;
    assert_eq!(automation.status,403,"an owner's automation credential is not a client key-holder account: {}",automation.body);
    let removed = f.call("DELETE","/api/orgs/org/members/member",&f.owner.token,None).await; assert_eq!(removed.status,200);
    assert_eq!(f.commit(&f.member.token,removed_payload).await.status,403,"a previously wrapped key and snapshot cannot outlive membership");
    assert_eq!(f.call("GET",&f.path("e2e/secrets"),&f.member.token,None).await.status,403);
    assert_eq!(f.read(&f.owner).await,before);
}

#[tokio::test]
async fn competing_holder_commits_have_one_winner_and_no_partial_loser_writes() {
    let f = Fixture::new(false,true).await; f.grant().await; let meta = f.snapshot().await; let before = f.read(&f.owner).await;
    let (a,ak) = f.payload(&meta,&before,&f.owner,&[&f.owner,&f.member]);
    let (b,bk) = f.payload(&meta,&before,&f.owner,&[&f.owner,&f.member]);
    let (ra,rb) = tokio::join!(f.commit(&f.owner.token,a),f.commit(&f.owner.token,b));
    let mut statuses = [ra.status,rb.status]; statuses.sort();
    assert_eq!(statuses,[200,409],"competing snapshots need exactly one winner: {} {}; {} {}",ra.status,ra.body,rb.status,rb.body);
    let winner = if ra.status==200 { ak } else { bk };
    f.assert_rotated(&before,&winner,&f.owner).await; f.assert_rotated(&before,&winner,&f.member).await;
    let after = f.snapshot().await; assert_eq!(after["key_generation"].as_u64().unwrap(),meta["key_generation"].as_u64().unwrap()+1);
    assert_eq!(f.audit().await.iter().filter(|r| r["action"]=="e2e.rekey").count(),1,"loser must not append a success audit");
    let verify = f.call("GET","/api/orgs/org/audit/verify",&f.owner.token,None).await; assert_eq!(verify.status,200); assert_eq!(verify.body["ok"],true);
}

#[tokio::test]
async fn rekey_requires_exact_live_ciphertexts_and_all_grantees_unless_explicitly_removed() {
    let f = Fixture::new(false,true).await; f.grant().await; let meta = f.snapshot().await; let before = f.read(&f.owner).await; let audit = f.audit().await;
    let (payload,_) = f.payload(&meta,&before,&f.owner,&[&f.owner,&f.member]);
    let mut omitted = payload.clone(); omitted["secrets"] = json!([]);
    let mut extra = payload.clone(); extra["secrets"].as_array_mut().unwrap().push(json!({"key_hash":oc::hash_token("/:EXTRA"),"key_enc":oc::encrypt_symmetric(&f.key,b"EXTRA"),"value_enc":oc::encrypt_symmetric(&f.key,b"extra"),"path_enc":oc::encrypt_symmetric(&f.key,b"/")}));
    let mut duplicate = payload.clone(); duplicate["secrets"].as_array_mut().unwrap().push(payload["secrets"][0].clone());
    let mut no_member = payload.clone(); no_member["grants"] = json!([payload["grants"][0]]);
    let mut duplicate_grant = payload.clone(); duplicate_grant["grants"].as_array_mut().unwrap().push(payload["grants"][0].clone());
    for (name,body) in [("omitted live secret",omitted),("unknown secret",extra),("duplicate secret",duplicate),("silent grantee removal",no_member),("duplicate grant",duplicate_grant)] {
        let r = f.commit(&f.owner.token,body).await;
        assert!(r.status>=400,"{name} must not commit: {} {}",r.status,r.body);
        assert_eq!(f.read(&f.owner).await,before); assert_eq!(f.read(&f.member).await["secrets"],before["secrets"]); assert_eq!(f.audit().await,audit);
        assert_eq!(f.snapshot().await["key_generation"],meta["key_generation"]);
    }
    let (mut remove,key) = f.payload(&meta,&before,&f.owner,&[&f.owner]); remove["remove_user"] = json!(f.member.id);
    let r = f.commit(&f.owner.token,remove).await; assert_eq!(r.status,200,"explicit atomic removal remains supported: {}",r.body);
    f.assert_rotated(&before,&key,&f.owner).await;
    assert_eq!(f.call("GET",&f.path("e2e/secrets"),&f.member.token,None).await.status,403);
    assert_eq!(f.snapshot().await["rekey_required"],false);
}

#[tokio::test]
async fn audit_failure_rolls_back_generation_pending_ciphertexts_and_wrapped_keys() {
    let f = Fixture::new(false,true).await; f.grant().await; f.revoke().await;
    let meta = f.snapshot().await; let before = f.read(&f.owner).await; let audit = f.audit().await;
    f.state.db().exec("CREATE TRIGGER client_rekey_audit_failure BEFORE INSERT ON audit WHEN NEW.action='e2e.rekey' BEGIN SELECT RAISE(ABORT,'client-rekey audit fixture failure'); END",&[]).await.unwrap();
    let (payload,key) = f.payload(&meta,&before,&f.owner,&[&f.owner]);
    let r = f.commit(&f.owner.token,payload.clone()).await;
    assert!(r.status>=400,"audit storage failure must abort the rekey: {} {}",r.status,r.body);
    assert_eq!(f.read(&f.owner).await,before); assert_eq!(f.audit().await,audit);
    let after = f.snapshot().await; assert_eq!(after["key_generation"],meta["key_generation"]); assert_eq!(after["membership_version"],meta["membership_version"]); assert_eq!(after["rekey_required"],true);
    f.state.db().exec("DROP TRIGGER client_rekey_audit_failure",&[]).await.unwrap();
    let r = f.commit(&f.owner.token,payload).await; assert_eq!(r.status,200,"failed transaction must leave the same snapshot retryable: {}",r.body);
    f.assert_rotated(&before,&key,&f.owner).await; assert_eq!(f.snapshot().await["rekey_required"],false);
    assert_eq!(f.audit().await.iter().filter(|r| r["action"]=="e2e.rekey").count(),1);
}

#[tokio::test]
async fn delegated_rekey_policy_is_admin_controlled_and_runner_cannot_claim_account_authority() {
    let f = Fixture::new(true,true).await; f.grant().await;
    let meta = f.snapshot().await; assert_eq!(meta["runner"]["rekey_authorized"],false,"runner rekey authority must be opt-in");
    let (_,runner_token,runner_keys) = f.runner.as_ref().unwrap();
    let policy = f.path("e2e/policy");
    for token in [&f.member.token,runner_token] {
        let r = f.call("PUT",&policy,token,Some(json!({"runner_rekey_authorized":true}))).await;
        assert!(matches!(r.status,401|403),"neither developer nor runner may self-authorize: {} {}",r.status,r.body);
    }
    let r = f.call("PUT",&policy,&f.owner.token,Some(json!({"runner_rekey_authorized":true}))).await; assert_eq!(r.status,200,"owner can explicitly authorize runner wrapping: {}",r.body);
    let enabled = f.snapshot().await; assert_eq!(enabled["runner"]["rekey_authorized"],true);
    let before = f.read(&f.owner).await; let (mut payload,_) = f.payload(&enabled,&before,&f.owner,&[&f.owner,&f.member]);
    payload["runner_wrapped_key"] = json!(oc::encrypt_to(&runner_keys.public,&oc::random_key()).unwrap());
    let r = f.commit(runner_token,payload).await; assert!(matches!(r.status,401|403),"runner is never an account commit caller: {} {}",r.status,r.body);
    assert_eq!(f.read(&f.owner).await,before);
    let r = f.call("PUT",&policy,&f.owner.token,Some(json!({"runner_rekey_authorized":false}))).await; assert_eq!(r.status,200);
    let integration = f.call("POST",&f.path("integrations"),&f.owner.token,Some(json!({"kind":"webhook","config":{"url":"https://sync.test.invalid/hook"}}))).await; assert_eq!(integration.status,200,"sealed integration fixture: {}",integration.body);
    let sync_path = format!("/api/integrations/{}/sync",integration.body["id"].as_str().unwrap());
    let queued = f.call("POST",&sync_path,&f.owner.token,Some(json!({}))).await; assert_eq!(queued.status,200,"delegated sync positive control must queue locally: {}",queued.body);
    f.revoke().await;
    let blocked = f.call("POST",&sync_path,&f.owner.token,Some(json!({}))).await; assert_eq!(blocked.status,409,"pending delegated sync must not enqueue work: {}",blocked.body);
    let jobs = f.call("GET","/api/runner/jobs",runner_token,None).await; assert_eq!(jobs.status,200); assert!(jobs.body["jobs"].as_array().unwrap().is_empty(),"already queued jobs must not release old key or ciphertext while pending");
    let pending = f.snapshot().await; let (payload,key) = f.payload(&pending,&before,&f.owner,&[&f.owner]);
    assert!(payload.get("runner_wrapped_key").is_none());
    let r = f.commit(&f.owner.token,payload).await; assert_eq!(r.status,200,"account holder can rotate without rewrapping to an unauthorized runner: {}",r.body);
    f.assert_rotated(&before,&key,&f.owner).await;
    let jobs = f.call("GET","/api/runner/jobs",runner_token,None).await; assert_eq!(jobs.status,200); assert!(jobs.body["jobs"].as_array().unwrap().is_empty(),"disconnected runner must receive no runnable payload after rotation");
    assert_eq!(f.snapshot().await["rekey_required"],false);
    let plain = f.call("GET",&f.path("secrets"),&f.owner.token,None).await; assert_eq!(plain.status,409,"delegated rekey must never add a server plaintext path");
}

#[tokio::test]
async fn cached_generation_secret_write_after_rekey_is_rejected_without_mutation() {
    let f = Fixture::new(false,true).await; let cached = f.snapshot().await; let before = f.read(&f.owner).await;
    let cached_write = json!({"expected_generation":cached["key_generation"],"secrets":[Fixture::ciphertext(&f.key,"stale-client-write")]});
    let (payload,key) = f.payload(&cached,&before,&f.owner,&[&f.owner]);
    let rotated = f.commit(&f.owner.token,payload).await; assert_eq!(rotated.status,200,"rotation positive control: {}",rotated.body);
    let current = f.snapshot().await; let data = f.read(&f.owner).await; let audit = f.audit().await;
    assert_eq!(current["key_generation"].as_u64().unwrap(),cached["key_generation"].as_u64().unwrap()+1);
    assert_eq!(f.unwrap(&f.owner,&data),key);
    let stale = f.call("PUT",&f.path("e2e/secrets"),&f.owner.token,Some(cached_write)).await;
    assert_eq!(stale.status,409,"ciphertext encrypted with a cached old-generation key must be refused: {}",stale.body);
    assert_eq!(f.read(&f.owner).await,data); assert_eq!(f.audit().await,audit);
    let after = f.snapshot().await; assert_eq!(after["key_generation"],current["key_generation"]); assert_eq!(after["membership_version"],current["membership_version"]); assert_eq!(after["rekey_required"],false);
    let fresh = json!({"expected_generation":current["key_generation"],"secrets":[Fixture::ciphertext(&key,"fresh-client-write")]});
    let written = f.call("PUT",&f.path("e2e/secrets"),&f.owner.token,Some(fresh)).await;
    assert_eq!(written.status,200,"a refreshed generation and key must still write: {}",written.body); assert_eq!(written.body["deployed"],1);
    let data = f.read(&f.owner).await;
    assert_eq!(oc::decrypt_symmetric(&key,data["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(),b"fresh-client-write");
}

#[tokio::test]
async fn cached_generation_grant_after_rekey_is_rejected_without_mutation() {
    let f = Fixture::new(false,true).await; let cached = f.snapshot().await; let before = f.read(&f.owner).await;
    let cached_grant = json!({"expected_generation":cached["key_generation"],"email":f.member.email,"wrapped_key":oc::encrypt_to(&f.member.keys.public,&f.key).unwrap()});
    let (payload,key) = f.payload(&cached,&before,&f.owner,&[&f.owner]);
    let rotated = f.commit(&f.owner.token,payload).await; assert_eq!(rotated.status,200,"rotation positive control: {}",rotated.body);
    let current = f.snapshot().await; let data = f.read(&f.owner).await; let audit = f.audit().await;
    let grants = f.call("GET",&f.path("e2e/grants"),&f.owner.token,None).await; assert_eq!(grants.status,200);
    assert_eq!(current["key_generation"].as_u64().unwrap(),cached["key_generation"].as_u64().unwrap()+1);
    assert_eq!(f.unwrap(&f.owner,&data),key);
    let stale = f.call("POST",&f.path("e2e/grant"),&f.owner.token,Some(cached_grant)).await;
    assert_eq!(stale.status,409,"a cached old-generation wrapper must not grant an unusable key: {}",stale.body);
    assert_eq!(f.read(&f.owner).await,data); assert_eq!(f.audit().await,audit);
    let after = f.snapshot().await; assert_eq!(after["key_generation"],current["key_generation"]); assert_eq!(after["membership_version"],current["membership_version"]); assert_eq!(after["rekey_required"],false);
    let still = f.call("GET",&f.path("e2e/grants"),&f.owner.token,None).await; assert_eq!(still.status,200); assert_eq!(still.body,grants.body);
    assert_eq!(f.call("GET",&f.path("e2e/secrets"),&f.member.token,None).await.status,403);
    let fresh = json!({"expected_generation":current["key_generation"],"email":f.member.email,"wrapped_key":oc::encrypt_to(&f.member.keys.public,&key).unwrap()});
    let granted = f.call("POST",&f.path("e2e/grant"),&f.owner.token,Some(fresh)).await;
    assert_eq!(granted.status,200,"a current-generation client wrapper must still grant access: {}",granted.body);
    let member = f.read(&f.member).await; assert_eq!(f.unwrap(&f.member,&member),key);
    assert_eq!(oc::decrypt_symmetric(&key,member["secrets"][0]["value_enc"].as_str().unwrap()).unwrap(),b"original");
    assert_eq!(f.snapshot().await["membership_version"].as_u64().unwrap(),current["membership_version"].as_u64().unwrap()+1);
}
