//! Unit tests for the OCSP crate.

use std::time::{Duration, SystemTime};

use keystore_pki::der;
use keystore_pki::ext;
use keystore_pki::x509;
use keystore_pki::{Extensions, KeyAlgorithm, KeyPair, SignatureAlgorithm, generate};

use crate::error::OcspError;
use crate::ext::OcspExtension;
use crate::name::GeneralName;
use crate::request::{CertificateId, OcspRequest, OcspRequestBuilder};
use crate::responder::Responder;
use crate::response::{
    BasicOcspResponse, BasicOcspResponseBuilder, CertStatus, OcspResponse, ResponderId,
    ResponseData, RevocationReason, SingleResponse,
};
use crate::transport::{HttpRequest, HttpResponse, Transport};
use crate::verify::{OcspVerifier, VerifyOptions};
use crate::{HashAlgorithm, ParsedCertificate};

const SIG: SignatureAlgorithm = SignatureAlgorithm::Sha256WithEcdsa;
const CA_DN: &str = "CN=Test CA";

struct Fixture {
    ca: KeyPair,
    ca_cert: Vec<u8>,
    leaf: Vec<u8>,
    leaf_serial: Vec<u8>,
    other_serial: Vec<u8>,
    third_serial: Vec<u8>,
    responder_key: KeyPair,
    responder_cert: Vec<u8>,
}

fn extensions(specs: &[&str]) -> Extensions {
    let mut extensions = Extensions::new();
    for spec in specs {
        ext::parse_spec(spec, &mut extensions).expect("extension spec");
    }
    extensions
}

fn issue_leaf(ca: &KeyPair, dn: &str) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let key = generate(KeyAlgorithm::Ec, 256)?;
    let certificate = x509::issue_with(
        &ca.private_key_pkcs8,
        CA_DN,
        &ca.public_key_spki,
        &key.public_key_spki,
        dn,
        SIG,
        365,
        &Extensions::new(),
    )?;
    let serial = ParsedCertificate::parse(&certificate)?.serial;
    Ok((certificate, serial))
}

fn fixture() -> crate::Result<Fixture> {
    let ca = generate(KeyAlgorithm::Ec, 256)?;
    let ca_extensions = extensions(&["BC=critical,ca:true", "KU=critical,keyCertSign,cRLSign"]);
    let ca_cert = x509::self_signed_with(&ca, CA_DN, 365, &ca_extensions)?;

    let (leaf, leaf_serial) = issue_leaf(&ca, "CN=Leaf")?;
    let (_, other_serial) = issue_leaf(&ca, "CN=Other Leaf")?;
    let (_, third_serial) = issue_leaf(&ca, "CN=Third Leaf")?;

    let responder_key = generate(KeyAlgorithm::Ec, 256)?;
    let responder_extensions =
        extensions(&["EKU=critical,OCSPSigning", "KU=critical,digitalSignature"]);
    let responder_cert = x509::issue_with(
        &ca.private_key_pkcs8,
        CA_DN,
        &ca.public_key_spki,
        &responder_key.public_key_spki,
        "CN=OCSP Responder",
        SIG,
        365,
        &responder_extensions,
    )?;

    Ok(Fixture {
        ca,
        ca_cert,
        leaf,
        leaf_serial,
        other_serial,
        third_serial,
        responder_key,
        responder_cert,
    })
}

fn cert_id(fixture: &Fixture, serial: &[u8]) -> crate::Result<CertificateId> {
    CertificateId::from_issuer(&fixture.ca_cert, serial, HashAlgorithm::Sha1)
}

fn responder(fixture: &Fixture) -> crate::Result<Responder> {
    Responder::new(
        &fixture.responder_cert,
        &fixture.responder_key.private_key_pkcs8,
        SIG,
    )
}

fn verifier(fixture: &Fixture) -> crate::Result<OcspVerifier> {
    OcspVerifier::new(&fixture.ca_cert)
}

fn simple_request(fixture: &Fixture) -> crate::Result<(OcspRequest, CertificateId)> {
    let id = cert_id(fixture, &fixture.leaf_serial)?;
    Ok((
        OcspRequestBuilder::new().add_request(id.clone()).build(),
        id,
    ))
}

#[test]
fn request_round_trip_and_pem() -> crate::Result<()> {
    let fixture = fixture()?;
    let first = cert_id(&fixture, &fixture.leaf_serial)?;
    let second = cert_id(&fixture, &fixture.other_serial)?;
    let ca_name = ParsedCertificate::parse(&fixture.ca_cert)?.subject_name;
    let request = OcspRequestBuilder::new()
        .add_request(first.clone())
        .add_request(second.clone())
        .requestor_name(GeneralName::DirectoryName(ca_name))
        .random_nonce(16)?
        .accept_basic_response()
        .build();

    assert_eq!(request.tbs_request.requests.len(), 2);
    assert_eq!(request.nonce()?.map(|nonce| nonce.len()), Some(16));
    assert_eq!(
        request.acceptable_response_types()?,
        vec![crate::OID_BASIC_RESPONSE.to_string()]
    );

    let der = request.to_der();
    let parsed = OcspRequest::from_der(&der)?;
    assert_eq!(parsed, request);

    let pem = request.to_pem()?;
    assert!(pem.starts_with("-----BEGIN OCSP REQUEST-----"));
    let from_pem = OcspRequest::from_pem(&pem)?;
    assert_eq!(from_pem, request);

    Ok(())
}

#[test]
fn signed_request_round_trip() -> crate::Result<()> {
    let fixture = fixture()?;
    let id = cert_id(&fixture, &fixture.leaf_serial)?;
    let ca_name = ParsedCertificate::parse(&fixture.ca_cert)?.subject_name;
    let signed = OcspRequestBuilder::new()
        .add_request(id)
        .requestor_name(GeneralName::DirectoryName(ca_name))
        .build_signed(
            &fixture.ca.private_key_pkcs8,
            SIG,
            vec![fixture.ca_cert.clone()],
        )?;

    let parsed = OcspRequest::from_der(&signed.to_der())?;
    assert!(parsed.signature.is_some());
    assert_eq!(parsed, signed);
    parsed.verify_signature(&fixture.ca_cert)?;

    let mut tampered = parsed.clone();
    if let Some(signature) = tampered.signature.as_mut() {
        signature.signature[0] ^= 0xff;
    }
    assert!(matches!(
        tampered.verify_signature(&fixture.ca_cert),
        Err(OcspError::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn response_round_trip_good_revoked_unknown() -> crate::Result<()> {
    let fixture = fixture()?;
    let first = cert_id(&fixture, &fixture.leaf_serial)?;
    let second = cert_id(&fixture, &fixture.other_serial)?;
    let third = cert_id(&fixture, &fixture.third_serial)?;
    let request = OcspRequestBuilder::new()
        .add_request(first.clone())
        .add_request(second.clone())
        .add_request(third.clone())
        .random_nonce(20)?
        .build();

    let statuses = vec![
        (first.clone(), CertStatus::Good),
        (
            second.clone(),
            CertStatus::Revoked {
                revocation_time: crate::now_seconds()? - 60,
                reason: Some(RevocationReason::KeyCompromise),
            },
        ),
        (third.clone(), CertStatus::Unknown),
    ];
    let responder = responder(&fixture)?;
    let response = responder.respond_with_statuses(&request, &statuses)?;

    let parsed = OcspResponse::from_der(&response.to_der())?;
    assert_eq!(parsed, response);
    assert!(parsed.is_successful());

    let verified = verifier(&fixture)?.verify(&parsed, &request)?;
    assert!(verified.delegated_responder);
    assert_eq!(verified.status_for(&first), Some(&CertStatus::Good));
    assert!(matches!(
        verified.status_for(&second),
        Some(status) if status.is_revoked()
    ));
    assert_eq!(verified.status_for(&third), Some(&CertStatus::Unknown));
    assert_eq!(verified.responses().len(), 3);

    let pem = parsed.to_pem()?;
    assert!(pem.starts_with("-----BEGIN OCSP RESPONSE-----"));
    assert_eq!(OcspResponse::from_pem(&pem)?, parsed);

    let basic_pem = parsed.basic_response()?.to_pem()?;
    assert_eq!(
        BasicOcspResponse::from_pem(&basic_pem)?,
        parsed.basic_response()?
    );

    Ok(())
}

#[test]
fn issuer_signed_response_has_no_delegation() -> crate::Result<()> {
    let fixture = fixture()?;
    let id = cert_id(&fixture, &fixture.leaf_serial)?;
    let request = OcspRequestBuilder::new()
        .add_request(id.clone())
        .random_nonce(16)?
        .build();
    let nonce = request.nonce()?.expect("request nonce");
    let now = crate::now_seconds()?;
    let data = ResponseData {
        version: 0,
        responder_id: ResponderId::from_certificate(&fixture.ca_cert)?,
        produced_at: now,
        responses: vec![SingleResponse::new(
            id.clone(),
            CertStatus::Good,
            now,
            Some(now + 3600),
        )],
        extensions: vec![OcspExtension::nonce(&nonce)],
    };
    let basic = BasicOcspResponse::sign(data, &fixture.ca.private_key_pkcs8, SIG, Vec::new())?;
    let response = OcspResponse::successful(&basic)?;
    let verified = verifier(&fixture)?.verify(&response, &request)?;
    assert!(!verified.delegated_responder);
    assert_eq!(verified.responder_certificate, fixture.ca_cert);
    assert_eq!(verified.status_for(&id), Some(&CertStatus::Good));
    Ok(())
}

#[test]
fn responder_uses_by_key_id() -> crate::Result<()> {
    let fixture = fixture()?;
    let (request, id) = simple_request(&fixture)?;
    let by_key = ResponderId::by_key_from_certificate(&fixture.responder_cert)?;
    let responder = responder(&fixture)?.with_responder_id(by_key);
    let response = responder.respond_all_good(&request)?;
    let verified = verifier(&fixture)?.verify(&response, &request)?;
    assert!(verified.delegated_responder);
    assert!(matches!(verified.responder_id(), ResponderId::ByKey(_)));
    assert_eq!(verified.status_for(&id), Some(&CertStatus::Good));
    Ok(())
}

#[test]
fn nonce_mismatch_is_rejected() -> crate::Result<()> {
    let fixture = fixture()?;
    let id = cert_id(&fixture, &fixture.leaf_serial)?;
    let request = OcspRequestBuilder::new()
        .add_request(id.clone())
        .nonce(b"the-request-nonce")
        .build();
    let now = crate::now_seconds()?;
    let data = ResponseData {
        version: 0,
        responder_id: ResponderId::from_certificate(&fixture.responder_cert)?,
        produced_at: now,
        responses: vec![SingleResponse::new(
            id,
            CertStatus::Good,
            now,
            Some(now + 3600),
        )],
        extensions: vec![OcspExtension::nonce(b"a-different-nonce")],
    };
    let basic = BasicOcspResponse::sign(
        data,
        &fixture.responder_key.private_key_pkcs8,
        SIG,
        vec![fixture.responder_cert.clone()],
    )?;
    let response = OcspResponse::successful(&basic)?;
    assert!(matches!(
        verifier(&fixture)?.verify(&response, &request),
        Err(OcspError::NonceMismatch)
    ));
    Ok(())
}

#[test]
fn missing_nonce_echo_is_rejected() -> crate::Result<()> {
    let fixture = fixture()?;
    let id = cert_id(&fixture, &fixture.leaf_serial)?;
    let request = OcspRequestBuilder::new()
        .add_request(id.clone())
        .nonce(b"must-be-echoed")
        .build();
    let responder = responder(&fixture)?;
    let mut response = responder.respond_all_good(&request)?;

    let mut data = response.basic_response()?.tbs_response_data;
    data.extensions
        .retain(|extension| extension.oid.as_str() != crate::OID_NONCE);
    let basic = BasicOcspResponse::sign(
        data,
        &fixture.responder_key.private_key_pkcs8,
        SIG,
        vec![fixture.responder_cert.clone()],
    )?;
    response = OcspResponse::successful(&basic)?;

    assert!(matches!(
        verifier(&fixture)?.verify(&response, &request),
        Err(OcspError::NonceMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_signature_is_rejected() -> crate::Result<()> {
    let fixture = fixture()?;
    let (request, _) = simple_request(&fixture)?;
    let response = responder(&fixture)?.respond_all_good(&request)?;
    let mut basic = response.basic_response()?;
    let last = basic.signature.len() - 1;
    basic.signature[last] ^= 0xff;
    let tampered = OcspResponse::successful(&basic)?;
    assert!(matches!(
        verifier(&fixture)?.verify(&tampered, &request),
        Err(OcspError::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn expired_next_update_is_rejected() -> crate::Result<()> {
    let fixture = fixture()?;
    let (request, id) = simple_request(&fixture)?;
    let now = crate::now_seconds()?;
    let mut builder =
        BasicOcspResponseBuilder::new(ResponderId::from_certificate(&fixture.responder_cert)?)?
            .produced_at_seconds(now - 7200);
    builder.add_response(id, CertStatus::Good, now - 7200, Some(now - 3600));
    let basic = builder.build(
        &fixture.responder_key.private_key_pkcs8,
        SIG,
        vec![fixture.responder_cert.clone()],
    )?;
    let response = OcspResponse::successful(&basic)?;
    assert!(matches!(
        verifier(&fixture)?.verify(&response, &request),
        Err(OcspError::Expired { .. })
    ));
    Ok(())
}

#[test]
fn wrong_cert_id_serial_is_rejected() -> crate::Result<()> {
    let fixture = fixture()?;
    let requested = cert_id(&fixture, &fixture.leaf_serial)?;
    let answered = cert_id(&fixture, &fixture.other_serial)?;

    let request = OcspRequestBuilder::new().add_request(requested).build();
    let other_request = OcspRequestBuilder::new().add_request(answered).build();
    let response = responder(&fixture)?.respond_all_good(&other_request)?;

    assert!(matches!(
        verifier(&fixture)?.verify(&response, &request),
        Err(OcspError::SerialMismatch { .. })
    ));
    Ok(())
}

#[test]
fn unknown_critical_extension_is_rejected() -> crate::Result<()> {
    let fixture = fixture()?;
    let (request, id) = simple_request(&fixture)?;
    let now = crate::now_seconds()?;
    let mut builder =
        BasicOcspResponseBuilder::new(ResponderId::from_certificate(&fixture.responder_cert)?)?
            .produced_at_seconds(now);
    builder.add_response(id, CertStatus::Good, now, Some(now + 3600));
    let builder =
        builder.response_extension(OcspExtension::new("1.2.3.4.5.6.7", true, vec![0x05, 0x00]));
    let basic = builder.build(
        &fixture.responder_key.private_key_pkcs8,
        SIG,
        vec![fixture.responder_cert.clone()],
    )?;
    let response = OcspResponse::successful(&basic)?;
    assert!(matches!(
        verifier(&fixture)?.verify(&response, &request),
        Err(OcspError::UnsupportedCriticalExtension(oid)) if oid.as_str() == "1.2.3.4.5.6.7"
    ));
    Ok(())
}

#[test]
fn non_critical_eku_is_configurable() -> crate::Result<()> {
    let fixture = fixture()?;
    let responder_key = generate(KeyAlgorithm::Ec, 256)?;
    let responder_cert = x509::issue_with(
        &fixture.ca.private_key_pkcs8,
        CA_DN,
        &fixture.ca.public_key_spki,
        &responder_key.public_key_spki,
        "CN=Non-critical OCSP Responder",
        SIG,
        365,
        &extensions(&["EKU=OCSPSigning", "KU=critical,digitalSignature"]),
    )?;
    let responder = Responder::new(&responder_cert, &responder_key.private_key_pkcs8, SIG)?;
    let (request, _) = simple_request(&fixture)?;
    let response = responder.respond_all_good(&request)?;

    assert!(matches!(
        verifier(&fixture)?.verify(&response, &request),
        Err(OcspError::OcspSigningEkuNotCritical)
    ));

    let relaxed = VerifyOptions {
        require_ocsp_signing_eku_critical: false,
        ..VerifyOptions::default()
    };
    let verifier = OcspVerifier::new(&fixture.ca_cert)?.with_options(relaxed);
    verifier.verify(&response, &request)?;
    Ok(())
}

#[test]
fn intermediate_responder_chain_is_verified() -> crate::Result<()> {
    let fixture = fixture()?;
    let intermediate_key = generate(KeyAlgorithm::Ec, 256)?;
    let intermediate_cert = x509::issue_with(
        &fixture.ca.private_key_pkcs8,
        CA_DN,
        &fixture.ca.public_key_spki,
        &intermediate_key.public_key_spki,
        "CN=Intermediate CA",
        SIG,
        365,
        &extensions(&[
            "BC=critical,ca:true,pathlen:0",
            "KU=critical,keyCertSign,cRLSign",
        ]),
    )?;
    let responder_key = generate(KeyAlgorithm::Ec, 256)?;
    let responder_cert = x509::issue_with(
        &intermediate_key.private_key_pkcs8,
        "CN=Intermediate CA",
        &intermediate_key.public_key_spki,
        &responder_key.public_key_spki,
        "CN=Chained OCSP Responder",
        SIG,
        365,
        &extensions(&["EKU=critical,OCSPSigning", "KU=critical,digitalSignature"]),
    )?;

    let (request, id) = simple_request(&fixture)?;
    let responder = Responder::new(&responder_cert, &responder_key.private_key_pkcs8, SIG)?
        .with_chain(vec![intermediate_cert]);
    let response = responder.respond_all_good(&request)?;
    let verified = verifier(&fixture)?.verify(&response, &request)?;
    assert!(verified.delegated_responder);
    assert_eq!(verified.status_for(&id), Some(&CertStatus::Good));
    Ok(())
}

#[test]
fn ber_encoded_request_is_accepted() -> crate::Result<()> {
    let fixture = fixture()?;
    let (request, _) = simple_request(&fixture)?;
    let der = request.to_der();
    let (_, start, end) = der::read_tlv_at(&der, 0)?;
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[start..end]);
    ber.extend_from_slice(&[0x00, 0x00]);

    let parsed = OcspRequest::from_der(&ber)?;
    assert_eq!(parsed.tbs_request.version, request.tbs_request.version);
    assert_eq!(
        parsed.tbs_request.requests.len(),
        request.tbs_request.requests.len()
    );
    assert!(
        parsed.tbs_request.requests[0]
            .cert_id
            .same_as(&request.tbs_request.requests[0].cert_id)
    );
    assert_eq!(parsed.nonce()?, request.nonce()?);
    Ok(())
}

#[test]
fn transport_check_returns_status() -> crate::Result<()> {
    let fixture = fixture()?;

    struct Loopback {
        responder: Responder,
    }
    impl Transport for Loopback {
        fn endpoint(&self, _certificate: &[u8], _issuer: &[u8]) -> crate::Result<String> {
            Ok("https://ocsp.test/".to_string())
        }

        fn send(&self, request: &HttpRequest) -> crate::Result<HttpResponse> {
            assert_eq!(request.method.as_str(), "POST");
            assert_eq!(request.url.as_str(), "https://ocsp.test/");
            assert!(request.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    && value.as_str() == "application/ocsp-request"
            }));
            let parsed = OcspRequest::from_der(&request.body)?;
            let response = self.responder.respond_all_good(&parsed)?;
            Ok(HttpResponse::new(
                200,
                vec![(
                    "Content-Type".to_string(),
                    "application/ocsp-response".to_string(),
                )],
                response.to_der(),
            ))
        }
    }

    let loopback = Loopback {
        responder: responder(&fixture)?,
    };
    let status = crate::check(&fixture.leaf, &fixture.ca_cert, &loopback)?;
    assert_eq!(status, CertStatus::Good);

    let detailed =
        crate::OcspClient::new(&loopback).check_detailed(&fixture.leaf, &fixture.ca_cert)?;
    assert_eq!(detailed.status, CertStatus::Good);
    assert_eq!(detailed.verified.responses().len(), 1);
    Ok(())
}

#[test]
fn transport_http_error_is_reported() -> crate::Result<()> {
    struct Failing;
    impl Transport for Failing {
        fn endpoint(&self, _certificate: &[u8], _issuer: &[u8]) -> crate::Result<String> {
            Ok("https://ocsp.test/".to_string())
        }
        fn send(&self, _request: &HttpRequest) -> crate::Result<HttpResponse> {
            Ok(HttpResponse::new(503, Vec::new(), Vec::new()))
        }
    }
    let fixture = fixture()?;
    assert!(matches!(
        crate::check(&fixture.leaf, &fixture.ca_cert, &Failing),
        Err(OcspError::HttpStatus(503))
    ));
    Ok(())
}

#[test]
fn next_update_optional_and_max_age() -> crate::Result<()> {
    let fixture = fixture()?;
    let (request, id) = simple_request(&fixture)?;
    let now = crate::now_seconds()?;
    let mut builder =
        BasicOcspResponseBuilder::new(ResponderId::from_certificate(&fixture.responder_cert)?)?
            .produced_at_seconds(now);
    builder.add_response(id.clone(), CertStatus::Good, now - 7200, None);
    let basic = builder.build(
        &fixture.responder_key.private_key_pkcs8,
        SIG,
        vec![fixture.responder_cert.clone()],
    )?;
    let response = OcspResponse::successful(&basic)?;

    let no_next_update = VerifyOptions {
        require_next_update: true,
        ..VerifyOptions::default()
    };
    assert!(matches!(
        OcspVerifier::new(&fixture.ca_cert)?
            .with_options(no_next_update)
            .verify(&response, &request),
        Err(OcspError::MissingNextUpdate)
    ));

    let max_age = VerifyOptions {
        max_age: Some(Duration::from_secs(3600)),
        ..VerifyOptions::default()
    };
    assert!(matches!(
        OcspVerifier::new(&fixture.ca_cert)?
            .with_options(max_age)
            .verify(&response, &request),
        Err(OcspError::TooOld { .. })
    ));

    // Without a policy that demands nextUpdate the response verifies.
    let verified = verifier(&fixture)?
        .with_now(SystemTime::now())
        .verify(&response, &request)?;
    assert_eq!(verified.status_for(&id), Some(&CertStatus::Good));
    Ok(())
}

#[test]
fn sha256_cert_id_is_supported() -> crate::Result<()> {
    let fixture = fixture()?;
    let id = CertificateId::from_issuer(
        &fixture.ca_cert,
        &fixture.leaf_serial,
        HashAlgorithm::Sha256,
    )?;
    assert_eq!(id.issuer_name_hash.len(), 32);
    let issuer = ParsedCertificate::parse(&fixture.ca_cert)?;
    id.verify_issuer(&issuer)?;

    let request = OcspRequestBuilder::new().add_request(id.clone()).build();
    let responder = responder(&fixture)?;
    let response = responder.respond_all_good(&request)?;
    let verified = verifier(&fixture)?.verify(&response, &request)?;
    assert_eq!(verified.status_for(&id), Some(&CertStatus::Good));
    Ok(())
}

#[test]
fn generalized_time_forms() -> crate::Result<()> {
    use crate::time::{encode_generalized_time, parse_generalized_time};

    let seconds = 1_735_689_599; // 2024-12-31T23:59:59Z
    let encoded = encode_generalized_time(seconds)?;
    let expected: &[u8] = b"20241231235959Z";
    assert_eq!(&encoded[2..], expected);
    assert_eq!(parse_generalized_time("20241231235959Z")?, seconds);
    assert_eq!(parse_generalized_time("20241231235959.123Z")?, seconds);
    assert_eq!(parse_generalized_time("20250101005959+0100")?, seconds);
    assert_eq!(parse_generalized_time("20241231235959-0000")?, seconds);
    assert!(parse_generalized_time("20241331235959Z").is_err());
    Ok(())
}

#[test]
fn issuer_responder_id_and_certificate_id_hashes() -> crate::Result<()> {
    let fixture = fixture()?;
    let id = cert_id(&fixture, &fixture.leaf_serial)?;
    let issuer = ParsedCertificate::parse(&fixture.ca_cert)?;
    id.verify_issuer(&issuer)?;

    let mut wrong = id.clone();
    wrong.issuer_key_hash[0] ^= 0xff;
    assert!(matches!(
        wrong.verify_issuer(&issuer),
        Err(OcspError::CertIdMismatch(_))
    ));

    let by_name = ResponderId::from_certificate(&fixture.responder_cert)?;
    let responder_info = ParsedCertificate::parse(&fixture.responder_cert)?;
    assert!(by_name.matches(&responder_info)?);
    assert!(!by_name.matches(&issuer)?);
    Ok(())
}
