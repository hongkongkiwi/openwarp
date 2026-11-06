# OpenWarp Rust SDK

Async REST client using reqwest with rustls, serde, serde_json, tokio, and thiserror. This crate has its own empty workspace declaration and is not a member of the repository root workspace.

```rust,no_run
use openwarp_sdk::{Client, Error, LeaseInput};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::new("https://openwarp.example.invalid", "your-token")?;
    client.set_secret("env-id", "DATABASE_URL", "postgres://example", "/", "secret", "").await?;
    let secret = client.get_secret("env-id", "database_url").await?;
    let lease = client.create_lease("env-id", LeaseInput::default()).await?;
    Ok(())
}
```

`Client::new` is synchronous and fallible. Its API methods are async: `me`, `orgs`, `apps`, `envs`, `secrets`, `get_secret`, `set_secret`, `delete_secret`, `export`, `leases`, `create_lease`, and `audit`. Rust has no default arguments; pass `/`, `secret`, and an empty comment explicitly to `set_secret`. It sends empty tags, clearing any existing tags on update. The deployment result includes sync errors. Export returns text and typed secrets. Generic and PostgreSQL lease response fields are represented as optional fields.

The base URL is an HTTP(S) origin with an optional deployment prefix, without `/api`, credentials, query, or fragment. Use HTTPS in production. Segments are URL-encoded; dot segments are rejected and redirects disabled. Lookup and deletion match keys case-insensitively. Lookup returns `None` when absent; deletion is then a no-op. Multiple matching paths produce a local `Error::Api` with status 409 rather than selecting a secret arbitrarily.

`Error::Api { status, message, body }` retains non-success response data, including non-JSON text as a JSON string. Transport and decoding failures have separate variants. API error bodies and messages can contain sensitive data. Secret and Lease deliberately do not derive Debug.

## Verification

Two unit tests cover encoded URL construction, deployment prefixes, and rejected URL inputs without a server. No cargo commands were run, no dependencies downloaded, and no build or tests executed. The crate and example are not verified to compile. When dependency access is authorized, `cargo test --manifest-path sdk/rust/Cargo.toml` from the repository root is the intended check, not evidence of a passing result.
