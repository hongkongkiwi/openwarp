// Reuse the isolated HTTP fixture, without changing its independent renewal assertions.
include!("device_remaining.rs");

#[tokio::test]
async fn default_device_lifecycle_does_not_require_a_tpm() {
    let s=Server::start().await;let (token,_,ca)=setup(&s).await;
    let policy=s.call(Method::GET,&format!("/api/pki/cas/{}/attestation",ca),Some(&token),None).await;
    assert_eq!(policy.status,200);assert_eq!(policy.body["required"],false);
    let d=device(&s,&token,&ca).await;let key=rcgen::KeyPair::generate().unwrap();
    let issued=enroll(&s,&token,&d,&key).await;assert_eq!(issued["attested"],false);
    let replacement=rcgen::KeyPair::generate().unwrap();let c=challenge(&s,&d,&csr(&replacement)).await;
    let renewed=finish(&s,&c,&key,None).await;assert_eq!(renewed.status,200,"{:?}",renewed.body);
    assert_eq!(renewed.body["attested"],false);
}

#[tokio::test]
async fn expiry_email_is_delivered_once_per_recipient_per_day() {
    let s=Server::start().await; let (token,org,ca)=setup(&s).await;
    let d=device(&s,&token,&ca).await;
    let r=s.post(&format!("/api/pki/cas/{}/issue",ca),Some(&token),json!({"device_id":d,"days":6})).await;
    assert_eq!(r.status,200,"{:?}",r.body);
    let path=format!("/api/orgs/{}/pki/expiry-notify",org);
    let r=s.post(&path,Some(&token),json!({})).await;
    assert_eq!(r.status,200,"{:?}",r.body); assert_eq!(r.body["sent"],1); assert_eq!(r.body["failed"],0);
    let messages=s.inbox.lock().unwrap().clone();
    let alerts:Vec<_>=messages.iter().filter(|m|m["subject"]=="OpenWarp device certificates need renewal").collect();
    assert_eq!(alerts.len(),1); assert_eq!(alerts[0]["to"],"renew@test.invalid");
    let text=alerts[0]["text"].as_str().unwrap(); assert!(text.contains("Expires within 7 days: 1"));
    assert!(!text.contains("PRIVATE KEY")); assert!(!text.contains("owdev_"));
    let r=s.post(&path,Some(&token),json!({})).await;
    assert_eq!(r.status,200); assert_eq!(r.body["sent"],0); assert_eq!(r.body["failed"],0);
    assert_eq!(s.post(&path,None,json!({})).await.status,401);
}

#[tokio::test]
async fn enrolled_p384_and_ed25519_keys_can_self_renew() {
    let s=Server::start().await; let (token,_,ca)=setup(&s).await;
    for (algorithm,signature_algorithm) in [(&rcgen::PKCS_ECDSA_P384_SHA384,keystore_pki::SignatureAlgorithm::Sha384WithEcdsa),(&rcgen::PKCS_ED25519,keystore_pki::SignatureAlgorithm::Ed25519)] {
        let d=device(&s,&token,&ca).await;
        let key=rcgen::KeyPair::generate_for(algorithm).unwrap(); enroll(&s,&token,&d,&key).await;
        let replacement=rcgen::KeyPair::generate().unwrap(); let c=challenge(&s,&d,&csr(&replacement)).await;
        let signature=keystore_pki::sign(signature_algorithm,&key.serialize_der(),c["challenge"].as_str().unwrap().as_bytes()).unwrap();
        let r=s.post("/api/pki/renew",None,json!({"challenge_id":c["challenge_id"],"signature":Base64::encode_string(&signature)})).await;
        assert_eq!(r.status,200,"{:?}",r.body);
    }
}

#[tokio::test]
async fn builtin_tpm_requires_admin_pin_and_fresh_evidence() {
    let s=Server::start().await; let (token,_,ca)=setup(&s).await; let d=device(&s,&token,&ca).await;
    let pin=include_str!("fixtures/tpm/ak-public.b64").trim();
    let manifest:Value=serde_json::from_str(include_str!("fixtures/tpm/manifest.json")).unwrap();
    let policy=manifest["expected_pcr_digest"].as_str().unwrap();
    let path=format!("/api/pki/devices/{}/tpm",d);
    assert_eq!(s.call(Method::PUT,&path,None,Some(json!({"ak_public":pin,"pcr_digest":policy}))).await.status,401);
    let r=s.call(Method::PUT,&path,Some(&token),Some(json!({"ak_public":pin,"pcr_digest":policy}))).await;
    assert_eq!(r.status,200,"{:?}",r.body);
    let r=s.call(Method::PUT,&format!("/api/pki/cas/{}/attestation",ca),Some(&token),Some(json!({"mode":"tpm2","required":true}))).await;
    assert_eq!(r.status,200,"{:?}",r.body);
    let r=s.post(&format!("/api/pki/devices/{}/enrollment",d),Some(&token),json!({})).await; assert_eq!(r.status,200);
    let code=r.body["code"].clone(); let key=rcgen::KeyPair::generate().unwrap();
    let r=s.post("/api/pki/enroll",None,json!({"code":code,"csr":csr(&key)})).await;
    assert_eq!(r.status,403,"required TPM evidence must block: {:?}",r.body);
    let evidence:Value=serde_json::from_str(include_str!("fixtures/tpm/evidence.json")).unwrap();
    let r=s.post("/api/pki/enroll",None,json!({"code":code,"csr":csr(&key),"tpm_evidence":evidence})).await;
    assert_eq!(r.status,403,"evidence for another CSR/nonce must not enroll: {:?}",r.body);
    let inventory=s.get(&d,&token).await; assert!(inventory["active_cert"].is_null());
}
