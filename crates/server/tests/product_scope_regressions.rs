include!("product_features.rs");

async fn regression_cookie_call(f: &Fixture, method: Method, path: &str, token: &str, body: Option<Value>) -> Reply {
    let mut req = Request::builder().method(method).uri(path)
        .header("host", "openwarp.test.invalid").header("cookie", format!("ow_session={}", token));
    if body.is_some() { req = req.header("content-type", "application/json"); }
    let mut req = req.body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty)).unwrap();
    req.extensions_mut().insert(PeerAddr("192.0.2.10".parse().unwrap()));
    let response = f.app.clone().oneshot(req).await.expect("in-process cookie request");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024).await.expect("cookie response body");
    Reply { status, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
}

fn regression_denied(reply: &Reply) -> bool {
    matches!(reply.status, 401 | 403) && reply.body["error"].is_string()
}

#[tokio::test]
async fn regression_cookie_workload_scopes() {
    let f = Fixture::new().await;
    f.put("dev", json!([{"key":"CONTROL","value":"workload-control"}])).await;
    f.put("prod", json!([{"key":"PROD_ONLY","value":"production-control"}])).await;
    let trust = f.trust(trust_body(), OWNER).await;
    let login = f.exchange(&trust, &signed(&claims("cookie-regression")), 200).await;
    let token = access_token(&login);
    let control = f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 200).await;
    assert_eq!(secret(&control["secrets"], "CONTROL", "/")["value"], "workload-control");
    let read = regression_cookie_call(&f, Method::GET, "/api/envs/prod/secrets", token, None).await;
    let write = regression_cookie_call(&f, Method::PUT, "/api/envs/dev/secrets", token,
        Some(json!({"secrets":[{"key":"COOKIE_WRITE","value":"must-not-land"}]}))).await;
    let mcp = regression_cookie_call(&f, Method::POST, "/mcp", token,
        Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_secret","arguments":{"env_id":"dev","key":"COOKIE_MCP","value":"must-not-land"}}}))).await;
    let mcp_denied = regression_denied(&mcp) || (mcp.status == 200 && (mcp.body["error"].is_object() || mcp.body["result"]["isError"] == true));
    let after = f.secrets("dev").await;
    let unchanged = !after.as_array().unwrap().iter().any(|s| s["key"] == "COOKIE_WRITE" || s["key"] == "COOKIE_MCP");
    assert!(regression_denied(&read) && regression_denied(&write) && mcp_denied && unchanged,
        "cookie workload scope escaped: GET prod={}, PUT dev={}, POST mcp={}, writes_absent={}", read.status, write.status, mcp.status, unchanged);
}

#[tokio::test]
async fn regression_cookie_pat_and_oauth_transit_denied() {
    let f = Fixture::new().await;
    let key = f.transit_key("cookie-regression", "org-a", OWNER).await;
    let plain = oc::b64(b"cookie transit control");
    let encrypted = f.transit(&key, "encrypt", OWNER, json!({"plaintext":plain,"context":""}), 200).await;
    let cipher = json!({"ciphertext":encrypted["ciphertext"],"context":""});
    let path = format!("{}/{}/decrypt", KEYS, key);
    let session_list = regression_cookie_call(&f, Method::GET, KEYS, OWNER, None).await;
    assert_eq!(session_list.status, 200, "valid session cookie must retain transit key access");
    let session_decrypt = regression_cookie_call(&f, Method::POST, &path, OWNER, Some(cipher.clone())).await;
    assert_eq!(session_decrypt.status, 200, "valid session cookie must retain transit decryption");
    assert_eq!(session_decrypt.body["plaintext"], plain);
    f.pat("cookie-env-pat", "dev", "secrets:read").await;
    f.sql("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,resource,expires_at,created_at) VALUES(?,'fixture-client','owner','secrets:read','',?,?)",
        &[json!(oc::hash_token("cookie-oauth-secret-only")), json!(now()+300), json!(now())]).await;
    let mut outcomes = Vec::new();
    let mut denied = true;
    for (kind, token) in [("PAT", "cookie-env-pat"), ("OAuth", "cookie-oauth-secret-only")] {
        f.expect(Method::GET, "/api/envs/dev/secrets", Some(token), None, 200).await;
        f.expect(Method::GET, KEYS, Some(token), None, 403).await;
        f.transit(&key, "decrypt", token, cipher.clone(), 403).await;
        let list = regression_cookie_call(&f, Method::GET, KEYS, token, None).await;
        let decrypt = regression_cookie_call(&f, Method::POST, &path, token, Some(cipher.clone())).await;
        outcomes.push(format!("{} GET keys={}, POST decrypt={}", kind, list.status, decrypt.status));
        denied &= regression_denied(&list) && regression_denied(&decrypt);
    }
    assert!(denied, "cookie credentials escaped transit scope: {}", outcomes.join("; "));
}

#[tokio::test]
async fn regression_encoded_transit_action_scope() {
    let f = Fixture::new().await;
    let key = f.transit_key("encoded-action-regression", "org-a", OWNER).await;
    let plain = oc::b64(b"encoded transit control");
    let encrypted = f.transit(&key, "encrypt", OWNER, json!({"plaintext":plain,"context":""}), 200).await;
    let cipher = json!({"ciphertext":encrypted["ciphertext"],"context":""});
    f.pat("manage-only-pat", "", "transit:manage").await;
    f.expect(Method::GET, KEYS, Some("manage-only-pat"), None, 200).await;
    assert_eq!(f.transit(&key, "decrypt", OWNER, cipher.clone(), 200).await["plaintext"], plain);
    assert_eq!(f.transit(&key, "%64ecrypt", OWNER, cipher.clone(), 200).await["plaintext"], plain);
    f.transit(&key, "decrypt", "manage-only-pat", cipher.clone(), 403).await;
    f.transit(&key, "%64ecrypt", "manage-only-pat", cipher, 403).await;
}
