#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn system_time() -> std::time::SystemTime { std::time::SystemTime::now() }

#[cfg(target_arch = "wasm32")]
pub(crate) fn system_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn offset_datetime() -> time::OffsetDateTime { time::OffsetDateTime::now_utc() }

#[cfg(target_arch = "wasm32")]
pub(crate) fn offset_datetime() -> time::OffsetDateTime {
    let millis = js_sys::Date::now() as i64;
    time::OffsetDateTime::from_unix_timestamp(millis.div_euclid(1000)).expect("JS date is in range")
        + time::Duration::milliseconds(millis.rem_euclid(1000))
}
