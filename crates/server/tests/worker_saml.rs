//! Explicit workerd coverage. Run with scripts/worker-saml-smoke.sh, not a native Server fixture.
use base64ct::{Base64, Encoding};
use reqwest::{Client, Method, Response, Url};
use risaml::{AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
    IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy, RespondSso,
    Saml, SamlValidationContext, SpDescriptor, SsoEndpoint, Subject};
use rsa::pkcs8::EncodePrivateKey;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};

async fn call(client: &Client, base: &str, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Response {
    let mut request = client.request(method, format!("{}{}", base, path));
    if let Some(token) = token { request = request.bearer_auth(token); }
    if let Some(body) = body { request = request.json(&body); }
    request.send().await.expect("Worker HTTP request")
}

async fn json_status(response: Response, status: u16, context: &str) -> Value {
    let actual = response.status().as_u16();
    let text = response.text().await.expect("Worker response body");
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    assert_eq!(actual, status, "{}: HTTP {}; error={}", context, actual, body["error"]);
    assert!(!body.is_null(), "{}: expected a JSON response", context);
    body
}

async fn json_ok(response: Response, context: &str) -> Value { json_status(response, 200, context).await }

fn fixture_origin(name: &str) -> String {
    let raw = std::env::var(name).unwrap_or_else(|_| panic!("{} is required; run scripts/worker-saml-smoke.sh", name));
    let url = Url::parse(&raw).expect("fixture URL");
    assert!(url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port().is_some()
        && url.username().is_empty() && url.password().is_none() && url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
        "{} must be a disposable http://127.0.0.1:PORT origin", name);
    url.as_str().trim_end_matches('/').to_string()
}

async fn inbox(client: &Client, echo: &str) -> Vec<Value> {
    client.get(format!("{}/_requests", echo)).send().await.expect("email fixture")
        .error_for_status().expect("email fixture status").json().await.expect("email inbox")
}

async fn fresh_mail(client: &Client, echo: &str, before: usize, email: &str) -> String {
    for _ in 0..40 {
        let requests = inbox(client, echo).await;
        assert!(requests.len() >= before, "email fixture was reset during the test");
        for request in requests.iter().skip(before) {
            if request["path"] != "/mail" { continue; }
            let message: Value = serde_json::from_str(request["body"].as_str().expect("email body")).expect("email JSON");
            if message["to"] == email { return message["text"].as_str().expect("email text").to_string(); }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("fresh owner email must arrive through Worker email delivery");
}

async fn owner_email_grant(client: &Client, base: &str, echo: &str, email: &str, token: &str, cookie: &str) -> String {
    let before = inbox(client, echo).await.len();
    let start = json_ok(call(client, base, Method::POST, "/api/auth/step-up/start", Some(token), Some(json!({"risk": "very_risky"}))).await, "start owner email challenge").await;
    assert_eq!(start["risk"], "very_risky");
    assert_eq!(start["methods"], json!(["email"]));
    assert_eq!(start["email_sent"], true);
    let text = fresh_mail(client, echo, before, email).await;
    let code = text.split(|c: char| !c.is_ascii_digit()).find(|word| word.len() == 6).expect("emailed six-digit step-up code");
    let verified = json_ok(client.post(format!("{}/api/auth/step-up/verify", base)).header("cookie", cookie).header("origin", base)
        .json(&json!({"challenge": start["challenge"].as_str().expect("step-up challenge"), "email_code": code}))
        .send().await.expect("verify owner email challenge"), "verify owner email challenge").await;
    assert_eq!(verified["risk"], "very_risky");
    assert_eq!(verified["expires_in"], 300);
    verified["token"].as_str().expect("real owner step-up grant").to_string()
}

fn no_session(response: &Response) {
    assert!(!response.headers().get_all("set-cookie").iter().any(|v| v.to_str().unwrap_or("").contains("ow_session=")), "rejected SAML response must not issue a session");
}

#[tokio::test]
#[ignore = "requires disposable workerd and email fixture; run scripts/worker-saml-smoke.sh"]
async fn worker_saml_round_trip_validates_signatures_provisions_and_rejects_replay() {
    let base = fixture_origin("OPENWARP_TEST_WORKER_URL");
    let echo = fixture_origin("OPENWARP_TEST_MAIL_URL");
    assert_ne!(base, echo, "Worker and mail sink must have distinct fixture origins");
    let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(120)).build().unwrap();
    let before = inbox(&client, &echo).await.len();
    let email = format!("saml-owner-{}@test.invalid", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos());
    let password = "worker-saml-fixture-password";
    let owner = json_ok(call(&client, &base, Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": password}))).await, "register SAML owner").await;
    let org = owner["org_id"].as_str().expect("owner workspace");
    assert_eq!(owner["verification_required"], true);
    assert!(owner.get("token").is_none(), "unverified signup must not issue a session");

    let text = fresh_mail(&client, &echo, before, &email).await;
    let verification = text.split_whitespace().find(|word| word.contains("/api/auth/verify?token=")).expect("verification link must arrive through Worker email delivery");
    assert!(verification.starts_with(&format!("{}/api/auth/verify?token=", base)), "verification must target the disposable Worker");
    let verified = client.get(verification).send().await.expect("verify owner email");
    assert!([200, 302, 303].contains(&verified.status().as_u16()), "email verification status: {}", verified.status());
    let login = call(&client, &base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await;
    assert_eq!(login.status(), 200, "verified owner login");
    let cookie = login.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("ow_session=")).expect("owner login session cookie");
    assert!(cookie.contains("HttpOnly"), "owner browser session must be HttpOnly");
    let owner_cookie = cookie.split(';').next().unwrap().to_string();
    let login = json_ok(login, "owner login").await;
    let token = login["token"].as_str().expect("verified owner session");
    let me = json_ok(client.get(format!("{}/api/me", base)).header("cookie", &owner_cookie).send().await.expect("owner cookie session"), "owner cookie authenticates").await;
    assert_eq!(me["email"], email);
    let edition = json_ok(call(&client, &base, Method::GET, "/api/instance/edition", Some(token), None).await, "local development license").await;
    assert_eq!(edition["enterprise"], true, "fixture must enable the local development license");
    assert_eq!(edition["development"], true, "fixture must not use deployment license credentials");
    let grants = json_ok(call(&client, &base, Method::PUT, "/api/instance/features", Some(token), Some(json!({"org": org, "features": ["saml", "pki"]}))).await,
        "grant SAML and PKI (both must be compiled into the Worker)").await;
    assert_eq!(grants["org_id"], org);
    let features = grants["features"].as_array().expect("saved workspace feature grants");
    for feature in ["saml", "pki"] { assert!(features.iter().any(|v| v == feature), "workspace must hold the {} grant", feature); }

    // Match the native authorization suite's risaml IdP fixture and real RSA signature.
    let idp_rsa = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("idp rsa key");
    let idp_key_pem = idp_rsa.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).expect("idp key pem").to_string();
    let idp_key = rcgen::KeyPair::from_pem(&idp_key_pem).expect("idp key");
    let idp_params = rcgen::CertificateParams::new(vec!["idp.test".into()]).expect("idp params");
    let idp_cert = idp_params.self_signed(&idp_key).expect("idp cert");
    let idp_entity = "https://idp.test/metadata";
    let idp = Saml::idp(IdpConfig::builder(EntityId::try_new(idp_entity).unwrap())
        .sso_endpoint(SsoEndpoint::post("https://idp.test/sso").unwrap())
        .sso_endpoint(SsoEndpoint::redirect("https://idp.test/sso").unwrap())
        .credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(idp_key_pem)),
            signing_certificate: Some(CertificatePem::new(idp_cert.pem())),
            ..Credentials::default()
        })
        .validation(IdpValidationPolicy::strict())
        .build().unwrap()).unwrap();
    let config_url = format!("{}/api/orgs/{}/saml", base, org);
    let config = json!({
        "idp_entity_id": idp_entity, "metadata_xml": idp.metadata_xml().to_string(),
        "allow_unsigned_metadata": true, "auto_provision": true, "allowed_domains": "test.invalid"
    });
    let unproved = json_status(call(&client, &base, Method::PUT, &format!("/api/orgs/{}/saml", org), Some(token), Some(config.clone())).await,
        428, "SAML configuration requires owner email proof").await;
    assert_eq!(unproved["step_up_required"], true);
    assert_eq!(unproved["risk"], "very_risky");
    assert_eq!(unproved["email_required"], true);
    assert_eq!(unproved["totp_required"], false);
    let grant = owner_email_grant(&client, &base, &echo, &email, token, &owner_cookie).await;
    let probe = json_status(client.put(&config_url).bearer_auth(token).header("x-openwarp-step-up", &grant)
        .json(&json!({})).send().await.expect("SAML route probe"), 400, "SAML route must validate its body, never skip missing capabilities").await;
    assert_eq!(probe["error"], "idp_entity_id is required", "probe must reach the enabled, licensed SAML handler");
    let saved = json_ok(client.put(&config_url).bearer_auth(token).header("x-openwarp-step-up", &grant).json(&config)
        .send().await.expect("configure SAML"), "invalid input must not spend the owner email grant").await;
    assert_eq!(saved["ok"], true);
    let reused = json_status(client.put(&config_url).bearer_auth(token).header("x-openwarp-step-up", &grant).json(&config)
        .send().await.expect("reuse SAML configuration grant"), 428, "successful SAML save must consume owner email proof").await;
    assert_eq!(reused["step_up_required"], true);
    assert_eq!(reused["risk"], "very_risky");

    let metadata = call(&client, &base, Method::GET, &format!("/api/auth/saml/{}/metadata", org), None, None).await;
    assert_eq!(metadata.status(), 200, "Worker SP metadata");
    let xml = metadata.text().await.expect("SP metadata XML");
    let sp = SpDescriptor::from_metadata_xml_for(EntityId::try_new(format!("{}/api/auth/saml/{}/metadata", base, org)).unwrap(), &xml, MetadataTrustPolicy::UnsignedForCompatibility).expect("SP descriptor");
    let start = call(&client, &base, Method::GET, &format!("/api/auth/saml/{}/start", org), None, None).await;
    assert_eq!(start.status(), 307, "Worker SAML start");
    let location = start.headers().get("location").expect("SAML redirect").to_str().unwrap();
    assert!(location.starts_with("https://idp.test/sso?"), "SAML start must redirect to configured IdP");
    let query = location.split_once('?').expect("SAML redirect query").1.to_string();
    let validation = SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility);
    let request = idp.receive_sso(&sp, BrowserInput::<AuthnRequest>::redirect(query), validation).expect("IdP verifies Worker AuthnRequest");
    let user_email = format!("saml-user-{}@test.invalid", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos());
    let response = idp.respond_sso(&sp, &request, Subject::new(NameId::new(&user_email, None), Vec::new()), RespondSso::post()).expect("IdP signs response");
    let form = response.post_form().expect("SAML response form");
    let fields: Vec<(&str, String)> = form.fields().iter().map(|f| (f.name(), f.value().to_string())).collect();
    let acs = format!("{}/api/auth/saml/{}/acs", base, org);

    let mut tampered = fields.clone();
    let encoded = &mut tampered.iter_mut().find(|(name, _)| *name == "SAMLResponse").expect("SAMLResponse field").1;
    let mut signed_xml = String::from_utf8(Base64::decode_vec(encoded).expect("SAML response base64")).expect("SAML response XML");
    let marker = "<ds:SignatureValue>";
    let index = signed_xml.find(marker).expect("IdP signature value") + marker.len();
    let replacement = if signed_xml.as_bytes()[index] == b'A' { "B" } else { "A" };
    signed_xml.replace_range(index..index + 1, replacement);
    *encoded = Base64::encode_string(signed_xml.as_bytes());
    let invalid = client.post(&acs).form(&tampered).send().await.expect("tampered ACS request");
    assert_eq!(invalid.status(), 400, "invalid RSA signature must be rejected");
    no_session(&invalid);
    assert!(invalid.text().await.unwrap().contains("SAML validation failed"), "tampering must fail SAML validation, not request lookup");

    let accepted = client.post(&acs).form(&fields).send().await.expect("valid ACS request");
    assert_eq!(accepted.status(), 303, "valid signed SAML response must issue a browser session");
    assert_eq!(accepted.headers().get("location").unwrap(), &format!("/#org={}", org));
    let cookie = accepted.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).find(|v| v.starts_with("ow_session=")).expect("SAML session cookie");
    assert!(cookie.contains("HttpOnly"), "SAML browser session must be HttpOnly");
    let session_cookie = cookie.split(';').next().unwrap().to_string();
    let me = json_ok(client.get(format!("{}/api/me", base)).header("cookie", &session_cookie).send().await.expect("SAML session request"), "SAML session authenticates").await;
    assert_eq!(me["email"], user_email);
    let orgs = json_ok(client.get(format!("{}/api/orgs", base)).header("cookie", &session_cookie).send().await.expect("SAML memberships"), "SAML provisioned membership").await;
    assert!(orgs.as_array().expect("workspace list").iter().any(|row| row["id"] == org), "SAML user must join the configured workspace");

    let replay = client.post(&acs).form(&fields).send().await.expect("replayed ACS request");
    assert_eq!(replay.status(), 400, "a completed SAML response must not be reusable");
    no_session(&replay);
}
