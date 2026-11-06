//! The KMS bridge is native-only: it uses a blocking HTTP client, which the
//! Workers build does not link. A Worker deployment keeps the master key in a
//! binding; references to the bridge compile to these stubs.
pub struct Kms;

impl Kms {
    pub fn from_env() -> Result<Option<Kms>, String> { Ok(None) }
    pub fn key_id(&self) -> &str { "native-only" }
    pub fn wrap(&self, _plaintext: &[u8], _context: &str) -> Result<String, String> { Err("the KMS bridge requires the native server".into()) }
    pub fn unwrap(&self, _payload: &str, _context: &str) -> Result<Vec<u8>, String> { Err("the KMS bridge requires the native server".into()) }
}
