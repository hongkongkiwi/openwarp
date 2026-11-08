//! SAML time-window and status validation.

use crate::constants::{status_code, ParserType};
use crate::error::{SamlError, TimeWindowField};
use crate::util::Value;
use crate::xml::{extract_with_limits, fields, parse_saml_utc_date_time, XmlLimits};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

fn parse(ts: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(ts, &Rfc3339).ok()
}

pub(crate) fn offset_datetime_from_system_time(
    instant: SystemTime,
) -> Result<OffsetDateTime, SamlError> {
    let converted = match instant.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => Duration::try_from(elapsed)
            .ok()
            .and_then(|elapsed| OffsetDateTime::UNIX_EPOCH.checked_add(elapsed)),
        Err(error) => Duration::try_from(error.duration())
            .ok()
            .and_then(|elapsed| OffsetDateTime::UNIX_EPOCH.checked_sub(elapsed)),
    };
    converted.ok_or_else(|| {
        SamlError::Invalid("validation instant is outside the supported SAML time range".into())
    })
}

/// Validate risaml's fail-closed expiration policy for an inbound LogoutRequest.
///
/// The protocol profile layer owns SAML lexical conformance. Values that are
/// lexically valid but cannot be represented by the runtime clock fail here as
/// a library time-window policy decision.
pub(crate) fn logout_request_not_on_or_after_deadline(
    extracted: &Value,
    now: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<Option<OffsetDateTime>, SamlError> {
    let Some(value) = extracted.get_str("request.notOnOrAfter") else {
        return Ok(None);
    };
    let normalized = parse_saml_utc_date_time(value).ok_or(SamlError::TimeWindowInvalid {
        field: TimeWindowField::LogoutRequestNotOnOrAfter,
    })?;
    let deadline =
        OffsetDateTime::parse(normalized, &Rfc3339).map_err(|_| SamlError::TimeWindowInvalid {
            field: TimeWindowField::LogoutRequestNotOnOrAfter,
        })?;
    let effective_deadline = deadline
        .checked_add(Duration::milliseconds(not_on_or_after_skew_ms))
        .ok_or(SamlError::TimeWindowInvalid {
            field: TimeWindowField::LogoutRequestNotOnOrAfter,
        })?;
    if now >= effective_deadline {
        return Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::LogoutRequestNotOnOrAfter,
        });
    }
    Ok(Some(effective_deadline))
}

/// Validate a `NotBefore` / `NotOnOrAfter` window.
///
/// `drift` is `(not_before_ms, not_on_or_after_ms)` added to the respective
/// bounds. When neither bound is present the document is treated as valid.
/// A present-but-unparseable timestamp fails closed (mirrors JS `Invalid Date`).
/// Bounds shifted outside the runtime's supported time range also fail closed
/// as a library safety policy.
pub fn verify_time(
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    drift: (i64, i64),
) -> bool {
    verify_time_at(
        not_before,
        not_on_or_after,
        drift,
        crate::clock::offset_datetime(),
    )
}

pub(crate) fn verify_time_at(
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    drift: (i64, i64),
    now: OffsetDateTime,
) -> bool {
    let (nb_drift, na_drift) = (
        Duration::milliseconds(drift.0),
        Duration::milliseconds(drift.1),
    );

    match (not_before, not_on_or_after) {
        (None, None) => true,
        (Some(nb), None) => match parse(nb) {
            Some(t) => t.checked_add(nb_drift).is_some_and(|bound| bound <= now),
            None => false,
        },
        (None, Some(na)) => match parse(na) {
            Some(t) => t.checked_add(na_drift).is_some_and(|bound| now < bound),
            None => false,
        },
        (Some(nb), Some(na)) => match (parse(nb), parse(na)) {
            (Some(b), Some(a)) => {
                b.checked_add(nb_drift).is_some_and(|bound| bound <= now)
                    && a.checked_add(na_drift).is_some_and(|bound| now < bound)
            }
            _ => false,
        },
    }
}

pub(crate) fn conditions_time_bounds(
    extracted: &Value,
) -> Result<(Option<&str>, Option<&str>), SamlError> {
    match extracted.get("conditions") {
        None => Ok((None, None)),
        Some(Value::Array(items)) if items.is_empty() => Ok((None, None)),
        Some(conditions @ Value::Object(_)) => Ok((
            conditions.get_str("notBefore"),
            conditions.get_str("notOnOrAfter"),
        )),
        Some(Value::Array(_) | Value::Null | Value::Str(_)) => Err(SamlError::Invalid(
            "Assertion Conditions must be absent or occur exactly once".into(),
        )),
    }
}

/// Check the two-tier `<StatusCode>` of a response.
///
/// Only `SAMLResponse` / `LogoutResponse` are checked; other parser types are
/// skipped. Success resolves to `Ok(())`; anything else is an error.
pub fn check_status(content: &str, parser_type: ParserType) -> Result<(), SamlError> {
    check_status_with_limits(content, parser_type, XmlLimits::default())
}

/// Check response status with explicit XML parser resource limits.
pub fn check_status_with_limits(
    content: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let fields = match parser_type {
        ParserType::SamlResponse => fields::login_response_status_fields(),
        ParserType::LogoutResponse => fields::logout_response_status_fields(),
        _ => return Ok(()),
    };
    let result = extract_with_limits(content, &fields, limits)?;
    match result.get_str("top") {
        Some(code) if code == status_code::SUCCESS => Ok(()),
        Some(code) if !code.is_empty() => Err(SamlError::StatusNotSuccess {
            top: code.to_string(),
            second: result
                .get_str("second")
                .filter(|second| !second.is_empty())
                .map(str::to_string),
        }),
        _ => Err(SamlError::UndefinedStatus),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    const RESPONSE: &str = include_str!("../tests/fixtures/response.xml");
    const FAILED: &str = include_str!("../tests/fixtures/failed_response.xml");

    #[test]
    fn system_time_conversion_supports_pre_unix_epoch() -> Result<(), Box<dyn std::error::Error>> {
        // Windows SystemTime represents 100 ns ticks; other platforms retain
        // this test's original sub-tick precision coverage.
        let fractional_nanos = if cfg!(windows) { 700 } else { 7 };
        let instant = SystemTime::UNIX_EPOCH
            .checked_sub(StdDuration::new(1, fractional_nanos))
            .ok_or("platform SystemTime cannot represent the test instant")?;

        assert_eq!(
            offset_datetime_from_system_time(instant)?.unix_timestamp_nanos(),
            -1_000_000_000 - i128::from(fractional_nanos)
        );
        Ok(())
    }

    #[test]
    fn system_time_conversion_preserves_nanoseconds() -> Result<(), Box<dyn std::error::Error>> {
        let fractional_nanos = if cfg!(windows) {
            234_567_800
        } else {
            234_567_890
        };
        let instant = SystemTime::UNIX_EPOCH
            .checked_add(StdDuration::new(1, fractional_nanos))
            .ok_or("platform SystemTime cannot represent the test instant")?;

        assert_eq!(
            offset_datetime_from_system_time(instant)?.unix_timestamp_nanos(),
            1_000_000_000 + i128::from(fractional_nanos)
        );
        Ok(())
    }

    #[test]
    fn time_window_basic() {
        assert!(verify_time(None, None, (0, 0)));
        assert!(verify_time(
            Some("2000-01-01T00:00:00Z"),
            Some("2999-01-01T00:00:00Z"),
            (0, 0)
        ));
        // expired
        assert!(!verify_time(None, Some("2000-01-01T00:00:00Z"), (0, 0)));
        // not yet valid
        assert!(!verify_time(Some("2999-01-01T00:00:00Z"), None, (0, 0)));
        // unparseable fails closed
        assert!(!verify_time(Some("not-a-date"), None, (0, 0)));
    }

    #[test]
    fn absent_conditions_remain_unbounded() -> Result<(), Box<dyn std::error::Error>> {
        let extracted = Value::Object(vec![("conditions".into(), Value::Array(Vec::new()))]);

        assert_eq!(conditions_time_bounds(&extracted)?, (None, None));
        Ok(())
    }

    #[test]
    fn drift_widens_window() {
        // expired, but a huge positive notOnOrAfter drift makes it valid again
        assert!(verify_time(
            None,
            Some("2000-01-01T00:00:00Z"),
            (0, 9_000_000_000_000)
        ));
        // not-yet-valid, but a huge negative notBefore drift makes it valid
        assert!(verify_time(
            Some("2999-01-01T00:00:00Z"),
            None,
            (-50_000_000_000_000, 0)
        ));
    }

    #[test]
    fn time_window_rejects_unrepresentable_shifted_bounds() -> Result<(), Box<dyn std::error::Error>>
    {
        let bound = "2000-01-01T00:00:00Z";
        let now = OffsetDateTime::parse("2025-01-01T00:00:00Z", &Rfc3339)?;

        for skew in [i64::MIN, i64::MAX] {
            assert!(!verify_time_at(Some(bound), None, (skew, 0), now));
            assert!(!verify_time_at(None, Some(bound), (0, skew), now));
            assert!(!verify_time_at(
                Some(bound),
                Some("2999-01-01T00:00:00Z"),
                (skew, 0),
                now,
            ));
            assert!(!verify_time_at(Some(bound), Some(bound), (0, skew), now));
        }
        let upper_bound = "9999-12-31T23:59:59Z";
        assert!(!verify_time_at(Some(upper_bound), None, (1_000, 0), now));
        assert!(!verify_time_at(None, Some(upper_bound), (0, 1_000), now));
        Ok(())
    }

    #[test]
    fn shifted_time_window_keeps_inclusive_start_and_exclusive_end(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::parse("2025-01-01T00:00:00Z", &Rfc3339)?;
        let before = Some("2024-12-31T23:59:59Z");
        let after = Some("2025-01-01T00:00:01Z");

        assert!(verify_time_at(before, None, (1_000, 0), now));
        assert!(!verify_time_at(before, None, (1_001, 0), now));
        assert!(!verify_time_at(None, after, (0, -1_000), now));
        assert!(verify_time_at(None, after, (0, -999), now));
        assert!(verify_time_at(before, after, (1_000, -999), now));
        assert!(!verify_time_at(before, after, (1_000, -1_000), now));
        Ok(())
    }

    #[test]
    fn status_success_and_two_tier_failure() -> Result<(), Box<dyn std::error::Error>> {
        check_status(RESPONSE, ParserType::SamlResponse)?;
        // request types are skipped
        check_status(RESPONSE, ParserType::SamlRequest)?;

        match check_status(FAILED, ParserType::SamlResponse) {
            Err(SamlError::StatusNotSuccess { top, second }) => {
                assert_eq!(top, status_code::REQUESTER);
                assert_eq!(second.as_deref(), Some(status_code::INVALID_NAME_ID_POLICY));
            }
            other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
        }
        Ok(())
    }
}
