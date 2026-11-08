//! GeneralizedTime and Unix-time helpers.
//!
//! OCSP carries every timestamp as a GeneralizedTime, which always has a
//! four-digit year, seconds and a trailing `Z` in DER. The parser accepts the
//! wider BER forms (missing seconds, fractional seconds, numeric zone offsets)
//! because responders in the wild emit them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keystore_pki::der::{self, Reader};

use crate::error::{OcspError, Result};

/// Seconds since the Unix epoch for `time`.
pub fn system_time_to_seconds(time: SystemTime) -> Result<i64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_secs())
            .map_err(|_| OcspError::Time("timestamp does not fit in an i64".into())),
        Err(before) => {
            let seconds = i64::try_from(before.duration().as_secs())
                .map_err(|_| OcspError::Time("timestamp does not fit in an i64".into()))?;
            Ok(-seconds)
        }
    }
}

/// The inverse of [`system_time_to_seconds`].
pub fn seconds_to_system_time(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

/// The current time as Unix seconds.
pub fn now_seconds() -> Result<i64> {
    system_time_to_seconds(SystemTime::now())
}

/// Encodes a Unix timestamp as the DER GeneralizedTime OCSP requires.
pub fn encode_generalized_time(seconds: i64) -> Result<Vec<u8>> {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(1..=9999).contains(&year) {
        return Err(OcspError::Time(format!(
            "GeneralizedTime cannot represent the year {year}"
        )));
    }
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    Ok(der::tlv(
        der::TAG_GENERALIZED_TIME,
        format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z").as_bytes(),
    ))
}

/// Reads a GeneralizedTime or UTCTime from `reader` and returns Unix seconds.
pub fn read_time(reader: &mut Reader<'_>) -> Result<i64> {
    let tag = reader
        .peek_tag()
        .ok_or_else(|| OcspError::Malformed("expected a time value".into()))?;
    if tag != der::TAG_GENERALIZED_TIME && tag != der::TAG_UTC_TIME {
        return Err(OcspError::Malformed(format!(
            "expected GeneralizedTime or UTCTime, found tag {tag:#04x}"
        )));
    }
    let content = reader.read_tagged(tag)?;
    let text = std::str::from_utf8(content)
        .map_err(|error| OcspError::Time(format!("time value is not ASCII: {error}")))?;
    if tag == der::TAG_UTC_TIME {
        parse_utc_time(text)
    } else {
        parse_generalized_time(text)
    }
}

/// Parses the UTCTime form used by certificates.
pub fn parse_utc_time(text: &str) -> Result<i64> {
    let text = text.trim();
    if text.len() < 11 {
        return Err(OcspError::Time(format!("truncated UTCTime {text:?}")));
    }
    let (digits, zone) = split_zone(text)?;
    if digits.len() != 10 && digits.len() != 12 && digits.len() != 14 {
        return Err(OcspError::Time(format!("bad UTCTime {text:?}")));
    }
    let year: i64 = digits[0..2]
        .parse()
        .map_err(|_| OcspError::Time(format!("bad UTCTime year in {text:?}")))?;
    // RFC 5280: 00..49 is 2000..2049, 50..99 is 1950..1999.
    let year = if year < 50 { 2000 + year } else { 1900 + year };
    parse_components(year, &digits[2..], zone, text)
}

/// Parses a GeneralizedTime in DER or BER form.
pub fn parse_generalized_time(text: &str) -> Result<i64> {
    let text = text.trim();
    if text.len() < 10 {
        return Err(OcspError::Time(format!(
            "truncated GeneralizedTime {text:?}"
        )));
    }
    let (digits, zone) = split_zone(text)?;
    let (whole, fraction) = match digits.find(['.', ',']) {
        Some(index) => (&digits[..index], Some(&digits[index + 1..])),
        None => (digits, None),
    };
    if fraction.is_some_and(|fraction| !fraction.bytes().all(|b| b.is_ascii_digit())) {
        return Err(OcspError::Time(format!(
            "bad fractional seconds in {text:?}"
        )));
    }
    if whole.len() < 10 || whole.len() > 14 {
        return Err(OcspError::Time(format!("bad GeneralizedTime {text:?}")));
    }
    let year: i64 = whole[0..4]
        .parse()
        .map_err(|_| OcspError::Time(format!("bad GeneralizedTime year in {text:?}")))?;
    parse_components(year, &whole[4..], zone, text)
}

/// Splits the digits of a timestamp from its trailing zone designator.
fn split_zone(text: &str) -> Result<(&str, i64)> {
    if let Some(digits) = text.strip_suffix('Z') {
        return Ok((digits, 0));
    }
    // A '+' or '-' can only be a zone designator after the date part.
    for (index, byte) in text.bytes().enumerate().skip(8) {
        if byte == b'+' || byte == b'-' {
            let digits = &text[..index];
            let zone_text = &text[index..];
            let sign = if zone_text.starts_with('+') { 1 } else { -1 };
            let body = &zone_text[1..];
            let offset = match body.len() {
                4 => {
                    let hours: i64 = body[0..2]
                        .parse()
                        .map_err(|_| OcspError::Time(format!("bad zone in {text:?}")))?;
                    let minutes: i64 = body[2..4]
                        .parse()
                        .map_err(|_| OcspError::Time(format!("bad zone in {text:?}")))?;
                    hours * 3600 + minutes * 60
                }
                2 => {
                    let hours: i64 = body
                        .parse()
                        .map_err(|_| OcspError::Time(format!("bad zone in {text:?}")))?;
                    hours * 3600
                }
                _ => return Err(OcspError::Time(format!("bad zone in {text:?}"))),
            };
            return Ok((digits, sign * offset));
        }
    }
    // BER permits local time with no designator; treat it as UTC because there
    // is no other defensible default.
    Ok((text, 0))
}

/// Parses the trailing YYMMDDHH[MM[SS]] fields of a timestamp.
fn parse_components(year: i64, rest: &str, zone_offset: i64, original: &str) -> Result<i64> {
    if rest.len() < 6 || !rest.len().is_multiple_of(2) {
        return Err(OcspError::Time(format!("bad time fields in {original:?}")));
    }
    let month: u32 = rest[0..2]
        .parse()
        .map_err(|_| OcspError::Time(format!("bad month in {original:?}")))?;
    let day: u32 = rest[2..4]
        .parse()
        .map_err(|_| OcspError::Time(format!("bad day in {original:?}")))?;
    let hour: i64 = rest[4..6]
        .parse()
        .map_err(|_| OcspError::Time(format!("bad hour in {original:?}")))?;
    let minute: i64 = if rest.len() >= 8 {
        rest[6..8]
            .parse()
            .map_err(|_| OcspError::Time(format!("bad minute in {original:?}")))?
    } else {
        0
    };
    let second: i64 = if rest.len() >= 10 {
        rest[8..10]
            .parse()
            .map_err(|_| OcspError::Time(format!("bad second in {original:?}")))?
    } else {
        0
    };
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(OcspError::Time(format!(
            "out-of-range time field in {original:?}"
        )));
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second - zone_offset)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Howard Hinnant's days_from_civil: days since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day = day as i64;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Howard Hinnant's civil_from_days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}
