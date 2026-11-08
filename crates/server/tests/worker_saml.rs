//! Explicit workerd coverage. Run with scripts/worker-saml-smoke.sh, not a native Server fixture.
use base64ct::{Base64, Encoding};
use reqwest::{Client, Method, Response};
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

async fn json_ok(response: Response, context: &str) -> Value {
    assert_eq!(response.status(), 200, "{}: expected HTTP 200", context);
    response.json().await.expect("Worker JSON response")
}

fn no_session(response: &Response) {
    assert!(!response.headers().get_all("set-cookie").iter().any(|v| v.to_str().unwrap_or("").contains("ow_session=")), "rejected SAML response must not issue a session");
}

#[tokio::test]
#[ignore = "requires disposable workerd and email fixture; run scripts/worker-saml-smoke.sh"]
async fn worker_saml_round_trip_validates_signatures_provisions_and_rejects_replay() {
    let base = std::env::var("OPENWARP_TEST_WORKER_URL").expect("OPENWARP_TEST_WORKER_URL is required").trim_end_matches('/').to_string();
    let echo = std::env::var("OPENWARP_TEST_MAIL_URL").expect("OPENWARP_TEST_MAIL_URL is required");
    let client = Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(120)).build().unwrap();
    let email = format!("saml-owner-{}@test.invalid", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos());
    let password = "worker-saml-fixture-password";
    let owner = json_ok(call(&client, &base, Method::POST, "/api/auth/register", None, Some(json!({"email": email, "password": password}))).await, "register SAML owner").await;
    let org = owner["org_id"].as_str().expect("owner workspace");
    assert_eq!(owner["verification_required"], true);
    assert!(owner.get("token").is_none(), "unverified signup must not issue a session");

    let mut verification = None;
    for _ in 0..40 {
        let inbox: Vec<Value> = client.get(format!("{}/_requests", echo)).send().await.expect("email fixture").error_for_status().expect("email fixture status").json().await.expect("email inbox");
        for request in inbox {
            if request["path"] != "/mail" { continue; }
            let message: Value = serde_json::from_str(request["body"].as_str().expect("email body")).expect("email JSON");
            if message["to"] != email { continue; }
            verification = message["text"].as_str().unwrap_or("").split_whitespace().find(|word| word.contains("/api/auth/verify?token=")).map(str::to_string);
            if verification.is_some() { break; }
        }
        if verification.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let verification = verification.expect("verification link must arrive through Worker email delivery");
    assert!(verification.starts_with(&format!("{}/api/auth/verify?token=", base)), "verification must target the disposable Worker");
    let verified = client.get(verification).send().await.expect("verify owner email");
    assert!([200, 302, 303].contains(&verified.status().as_u16()), "email verification status: {}", verified.status());
    let login = json_ok(call(&client, &base, Method::POST, "/api/auth/login", None, Some(json!({"email": email, "password": password}))).await, "owner login").await;
    let token = login["token"].as_str().expect("verified owner session");

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
    json_ok(call(&client, &base, Method::PUT, &format!("/api/orgs/{}/saml", org), Some(token), Some(json!({
        "idp_entity_id": idp_entity, "metadata_xml": idp.metadata_xml().to_string(),
        "allow_unsigned_metadata": true, "auto_provision": true, "allowed_domains": "test.invalid"
    }))).await, "configure SAML").await;

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
