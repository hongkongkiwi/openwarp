//! Operator-visible warnings. Workers has no stderr, so the wasm build writes
//! to the runtime console instead; native keeps stderr.

#[cfg(not(target_arch = "wasm32"))]
pub fn warn(message: &str) { eprintln!("{}", message); }

#[cfg(target_arch = "wasm32")]
pub fn warn(message: &str) { worker::console_warn!("{}", message); }
