#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn system_time() -> std::time::SystemTime { std::time::SystemTime::now() }

#[cfg(target_arch = "wasm32")]
pub(crate) fn system_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}
