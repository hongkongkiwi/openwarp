#![cfg(feature = "change-requests")]

include!("product_features.rs");

impl Fixture {
    async fn product_lock(&self, scope: &str, locked: bool) {
        let sql = match scope {
            "workspace" => "UPDATE orgs SET emergency_locked=? WHERE id='org-a'",
            "project" => "UPDATE apps SET emergency_locked=? WHERE id='app-a'",
            _ => unreachable!(),
        };
        self.sql(sql, &[json!(if locked { 1 } else { 0 })]).await;
    }
    async fn product_lockdown_denial(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) {
        let reply = self.expect(method, path, token, body, 403).await;
        assert!(reply["error"].as_str().unwrap().contains("lockdown"), "denial must identify emergency lockdown");
    }
}

#[tokio::test]
async fn lockdown_blocks_owner_transit_until_workspace_or_project_is_restored() {
    if !suite_gated() { return; }
    for scope in ["workspace", "project"] {
        let f = Fixture::new().await;
        let key = f.transit_key("lockdown-existing", "org-a", OWNER).await;
        let plaintext = oc::b64(b"lockdown transit fixture");
        let input = json!({"plaintext":plaintext,"context":"lockdown-fixture"});
        let encrypted = f.transit(&key, "encrypt", OWNER, input.clone(), 200).await;
        let cipher = json!({"ciphertext":encrypted["ciphertext"],"context":"lockdown-fixture"});
        let before = f.expect(Method::GET, KEYS, Some(OWNER), None, 200).await;
        let operations = [
            ("encrypt", input.clone()), ("decrypt", cipher.clone()),
            ("rewrap", cipher.clone()), ("rotate", json!({})),
        ];
        f.product_lock(scope, true).await;
        f.product_lockdown_denial(Method::POST, KEYS, Some(OWNER), Some(json!({"name":"lockdown-new"}))).await;
        f.product_lockdown_denial(Method::GET, KEYS, Some(OWNER), None).await;
        for (action, body) in &operations {
            f.product_lockdown_denial(Method::POST, &format!("{}/{}/{}", KEYS, key, action), Some(OWNER), Some(body.clone())).await;
        }
        f.product_lock(scope, false).await;
        assert_eq!(f.expect(Method::GET, KEYS, Some(OWNER), None, 200).await, before);
        f.transit_key("lockdown-new", "org-a", OWNER).await;
        for (action, body) in operations {
            let result = f.transit(&key, action, OWNER, body, 200).await;
            if action == "decrypt" { assert_eq!(result["plaintext"], plaintext); }
            if action == "rotate" { assert_eq!(result["current_version"], 2); }
        }
    }
}

#[tokio::test]
async fn lockdown_blocks_owner_workload_trusts_until_workspace_or_project_is_restored() {
    if !suite_gated() { return; }
    for scope in ["workspace", "project"] {
        let f = Fixture::new().await;
        let trust = f.trust(trust_body(), OWNER).await;
        let before = f.expect(Method::GET, TRUSTS, Some(OWNER), None, 200).await;
        assert!(before.to_string().contains(&trust));
        let mut body = trust_body(); body["subject"] = json!("repo:fixture:environment:staging");
        f.product_lock(scope, true).await;
        f.product_lockdown_denial(Method::POST, TRUSTS, Some(OWNER), Some(body.clone())).await;
        f.product_lockdown_denial(Method::GET, TRUSTS, Some(OWNER), None).await;
        f.product_lock(scope, false).await;
        assert_eq!(f.expect(Method::GET, TRUSTS, Some(OWNER), None, 200).await, before);
        let created = f.trust(body, OWNER).await;
        assert!(f.expect(Method::GET, TRUSTS, Some(OWNER), None, 200).await.to_string().contains(&created));
    }
}

#[tokio::test]
async fn lockdown_blocks_owner_change_requests_until_workspace_or_project_is_restored() {
    if !suite_gated() { return; }
    for scope in ["workspace", "project"] {
        let f = Fixture::new().await;
        let id = f.create_change(batch(), OWNER).await;
        let path = format!("/api/change-requests/{}", id);
        let list_path = "/api/orgs/org-a/change-requests";
        let before = f.expect(Method::GET, list_path, Some(OWNER), None, 200).await;
        let detail = f.change(&id).await;
        f.product_lock(scope, true).await;
        f.product_lockdown_denial(Method::POST, list_path, Some(OWNER), Some(batch())).await;
        f.product_lockdown_denial(Method::GET, list_path, Some(OWNER), None).await;
        f.product_lockdown_denial(Method::GET, &path, Some(OWNER), None).await;
        f.product_lock(scope, false).await;
        assert_eq!(f.expect(Method::GET, list_path, Some(OWNER), None, 200).await, before);
        assert_eq!(f.change(&id).await, detail);
        f.create_change(batch(), OWNER).await;
    }
}

#[tokio::test]
async fn lockdown_blocks_workload_exchange_without_consuming_proof_until_restored() {
    if !suite_gated() { return; }
    for scope in ["workspace", "project"] {
        let f = Fixture::new().await;
        let trust = f.trust(trust_body(), OWNER).await;
        access_token(&f.exchange(&trust, &signed(&claims("lockdown-control")), 200).await);
        let jwt = signed(&claims("lockdown-retry"));
        let body = json!({"trust_id":trust,"jwt":jwt});
        f.product_lock(scope, true).await;
        f.product_lockdown_denial(Method::POST, LOGIN, None, Some(body.clone())).await;
        f.product_lock(scope, false).await;
        let login = f.expect(Method::POST, LOGIN, None, Some(body), 200).await;
        access_token(&login);
    }
}
