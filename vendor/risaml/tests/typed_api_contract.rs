use risaml::{
    AcsEndpoint, AuthnRequest, EndpointUrl, EntityId, Idp, LogoutBinding, LogoutRequest, MessageId,
    NameIdCreationRequest, PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot,
    RelayStateParam, Saml, SamlError, SamlInstant, SloEndpoint, Sp, SsoEndpoint, SsoRequestBinding,
    SsoResponseBinding,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn typed_api_contract_exposes_role_markers() {
    assert_send_sync::<Saml<Sp>>();
    assert_send_sync::<Saml<Idp>>();
    let _: Option<SamlError> = None;
}

#[test]
fn typed_api_contract_reexports_raw_flow_types() {
    let _ = std::any::type_name::<risaml::raw::Binding>();
    let _ = std::any::type_name::<risaml::raw::FlowResult>();
    let _ = std::any::type_name::<risaml::raw::BindingContext>();
    let _ = std::any::type_name::<risaml::raw::HttpRequest>();
}

#[test]
fn typed_api_contract_reexports_config_builders() {
    let _ = std::any::type_name::<risaml::SpConfigBuilder>();
    let _ = std::any::type_name::<risaml::IdpConfigBuilder>();
    let _ = std::any::type_name::<risaml::AuthnRequestSigningPolicy>();
    let _ = std::any::type_name::<risaml::AuthnRequestValidationPolicy>();
}

#[test]
fn typed_api_contract_reexports_typed_binding_building_blocks(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_send_sync::<SsoRequestBinding>();
    assert_send_sync::<SsoResponseBinding>();
    assert_send_sync::<LogoutBinding>();
    assert_send_sync::<EndpointUrl>();
    assert_send_sync::<SsoEndpoint>();
    assert_send_sync::<AcsEndpoint>();
    assert_send_sync::<SloEndpoint>();
    assert_send_sync::<MessageId>();
    assert_send_sync::<RelayStateParam>();
    assert_send_sync::<SamlInstant>();
    assert_send_sync::<PendingAuthnRequest>();
    assert_send_sync::<PendingSnapshot<AuthnRequest>>();
    assert_send_sync::<PendingLogoutRequest>();
    assert_send_sync::<PendingSnapshot<LogoutRequest>>();
    assert_send_sync::<NameIdCreationRequest>();

    let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
    let pending = PendingAuthnRequest::try_new(
        MessageId::try_new("_request123")?,
        RelayStateParam::try_from_option(Some("relay".to_string()))?,
        acs,
        SsoResponseBinding::Post,
        EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let _: PendingSnapshot<AuthnRequest> = pending.snapshot();
    let logout_pending = PendingLogoutRequest::try_new(
        MessageId::try_new("_logout123")?,
        RelayStateParam::present_empty(),
        LogoutBinding::Redirect,
        EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let _: PendingSnapshot<LogoutRequest> = logout_pending.snapshot();
    let _ = SsoEndpoint::redirect("https://idp.example.com/sso")?;
    let _ = SloEndpoint::new(
        LogoutBinding::Redirect,
        EndpointUrl::try_new("https://idp.example.com/slo")?,
    );
    let _ = SsoRequestBinding::Redirect;
    Ok(())
}

#[test]
fn typed_api_contract_reexports_browser_and_model_types() {
    let _: for<'a> fn(&'a AuthnRequest) -> &'a SamlInstant = AuthnRequest::issue_instant;
    let _: for<'a> fn(&'a risaml::SsoResponse) -> &'a SamlInstant =
        risaml::SsoResponse::issue_instant;
    let _: for<'a> fn(&'a risaml::SsoSession) -> &'a SamlInstant =
        risaml::SsoSession::response_issue_instant;
    let _: for<'a> fn(&'a risaml::SsoSession) -> &'a SamlInstant =
        risaml::SsoSession::assertion_issue_instant;
    let _ = std::any::type_name::<risaml::BrowserInput<risaml::AuthnRequest>>();
    let _ = std::any::type_name::<risaml::FormField>();
    let _ = std::any::type_name::<risaml::Outbound<risaml::AuthnRequest>>();
    let _ = std::any::type_name::<risaml::Pending<risaml::AuthnRequest>>();
    let _ = std::any::type_name::<risaml::PostForm>();
    let _ = std::any::type_name::<risaml::Started<risaml::AuthnRequest>>();
    let _ = std::any::type_name::<risaml::Assertion>();
    let _ = std::any::type_name::<risaml::AssertionId>();
    let _ = std::any::type_name::<risaml::Attribute>();
    let _ = std::any::type_name::<risaml::AttributeValue>();
    let _ = std::any::type_name::<risaml::Attributes>();
    let _ = std::any::type_name::<risaml::AuthnSession>();
    let _ = std::any::type_name::<risaml::LogoutCompleted>();
    let _ = std::any::type_name::<risaml::LogoutRequest>();
    let _ = std::any::type_name::<risaml::LogoutResponse>();
    let _ = std::any::type_name::<risaml::NameId>();
    let _ = std::any::type_name::<risaml::NameIdPolicy>();
    let _ = std::any::type_name::<risaml::Received<risaml::SsoResponse>>();
    let _ = std::any::type_name::<risaml::RelayState>();
    let _ = risaml::MAX_RELAY_STATE_BYTES;
    let _ = std::any::type_name::<risaml::SessionIndex>();
    let _ = std::any::type_name::<risaml::SsoResponse>();
    let _ = std::any::type_name::<risaml::SsoSession>();
    let _ = std::any::type_name::<risaml::Subject>();
    let _ = std::any::type_name::<risaml::SubjectConfirmation>();
}
