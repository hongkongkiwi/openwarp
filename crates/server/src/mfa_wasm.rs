//! Second factors on the Workers build. WebAuthn, TOTP and mailed codes need
//! native libraries (webauthn-rs, the SMTP client and a durable mailbox), so a
//! Worker answers every factor endpoint with 501 and treats every account as
//! having no second factor. The native server exposes the real module.
use crate::app::{err, PeerAddr, Res, S};
use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, Json};
use serde::Deserialize;
use serde_json::Value;

const NATIVE_ONLY: &str = "two-factor authentication requires the native server";

pub fn email_available() -> bool { false }
pub async fn email_enabled(_: &S, _: &str) -> bool { false }
pub async fn methods(_: &S, _: &str) -> Vec<&'static str> { Vec::new() }
pub async fn required(_: &S, _: &str) -> bool { false }
pub async fn recovery_count(_: &S, _: &str) -> usize { 0 }
pub async fn issue_recovery_codes(_: &S, _: &str) -> Vec<String> { Vec::new() }
pub async fn confirm_totp(_: &S, _: &str, _: &str) -> bool { false }
pub async fn second_factor_ok(_: &S, _: &str, _: &str) -> bool { false }
pub async fn new_challenge(_: &S, _: &str) -> Result<String, (StatusCode, Json<Value>)> { Err(err(StatusCode::NOT_IMPLEMENTED, NATIVE_ONLY)) }
pub async fn challenge_user(_: &S, _: &str) -> Option<String> { None }
pub async fn consume_challenge(_: &S, _: &str) {}
pub async fn note_password_login(_: &S, _: &str) {}
pub async fn reauth_add(_: &S, _: &str, _: &Value) -> Result<(), (StatusCode, Json<Value>)> { Ok(()) }

fn unavailable<T>() -> Result<T, (StatusCode, Json<Value>)> { Err(err(StatusCode::NOT_IMPLEMENTED, NATIVE_ONLY)) }

#[derive(Deserialize)]
pub struct PasskeyRegisterReq {}
#[derive(Deserialize)]
pub struct MfaTokenReq {}
#[derive(Deserialize)]
pub struct PasskeyLoginReq {}

pub async fn status(State(_): State<S>, _: HeaderMap) -> Res { unavailable() }
pub async fn recovery_regenerate(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { unavailable() }
pub async fn totp_disable(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { unavailable() }
pub async fn email_enroll_start(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { unavailable() }
pub async fn email_enroll_verify(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { unavailable() }
pub async fn email_disable(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { unavailable() }
pub async fn passkey_register_start(State(_): State<S>, _: HeaderMap, _: Json<Value>) -> Res { unavailable() }
pub async fn passkey_register_finish(State(_): State<S>, _: HeaderMap, _: Json<PasskeyRegisterReq>) -> Res { unavailable() }
pub async fn passkey_delete(State(_): State<S>, _: HeaderMap, _: Path<String>, _: Json<Value>) -> Res { unavailable() }
pub async fn mfa_options(State(_): State<S>, _: Json<MfaTokenReq>) -> Res { unavailable() }
pub async fn email_login_send(State(_): State<S>, _: PeerAddr, _: Json<MfaTokenReq>) -> Res { unavailable() }
pub async fn passkey_login_start(State(_): State<S>, _: HeaderMap, _: Json<MfaTokenReq>) -> Res { unavailable() }
pub async fn passkey_login_finish(State(_): State<S>, _: PeerAddr, _: HeaderMap, _: Json<PasskeyLoginReq>) -> Result<(HeaderMap, Json<Value>), (StatusCode, Json<Value>)> { unavailable() }
