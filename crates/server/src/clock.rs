//! Wall clock. `SystemTime::now()` panics on wasm32-unknown-unknown, so the
//! Workers build reads the runtime clock through the JS bindings instead.

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
pub fn now() -> i64 { (js_sys::Date::now() / 1000.0) as i64 }

#[cfg(not(target_arch = "wasm32"))]
pub fn system_time() -> std::time::SystemTime { std::time::SystemTime::now() }

#[cfg(target_arch = "wasm32")]
pub fn system_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep_ms(ms: u64) { tokio::time::sleep(std::time::Duration::from_millis(ms)).await; }

// Workers has no Tokio timer; deferred work waits on the runtime's setTimeout.
#[cfg(target_arch = "wasm32")]
pub async fn sleep_ms(ms: u64) { worker::Delay::from(std::time::Duration::from_millis(ms)).await; }

/// UTC calendar parts for a Unix timestamp: (year, month, day, hour, minute, second).
/// Pure arithmetic, so both targets and the Postgres/DER formatters share it.
pub fn utc_parts(unix: i64) -> (i64, u8, u8, u8, u8, u8) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 { year += 1; }
    (year, month as u8, day as u8, (secs / 3600) as u8, ((secs % 3600) / 60) as u8, (secs % 60) as u8)
}

#[cfg(test)]
mod tests {
    use super::utc_parts;

    #[test]
    fn converts_known_timestamps() {
        assert_eq!(utc_parts(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(utc_parts(1_767_225_600), (2026, 1, 1, 0, 0, 0));
        // Leap day
        assert_eq!(utc_parts(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }
}
