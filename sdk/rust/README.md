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

## Generic management requests

`client.api::<serde_json::Value>(reqwest::Method::GET, &["capabilities"], None, &[]).await?` discovers public route templates. The public signature accepts a method, path segments relative to `/api`, an optional JSON value and a `&[(String, String)]` query list. Segments are individually encoded; query pairs preserve repeated keys. Use `&["envs", env_id, "integrations"]` to list configured integrations, or POST a JSON body to create one.

GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS are supported. Empty success responses decode from JSON null, so use `Value` or `Option<T>` when a route can return 204. HTTP failures retain status and body in `Error::Api`. Generic requests reject malformed encoding, controls, backslashes, URL-like segments and traversal after repeated decoding. Redirects stay disabled. Named wrappers retain their existing behavior.

The server applies the same permissions as direct HTTP requests. OAuth workspace management additionally requires `org:admin`; discovery does not grant access. Keep returned keys and error bodies out of logs.

`api_with_step_up(method, segments, body, query, step_up)` sends an existing verification grant through `X-OpenWarp-Step-Up` for one request. It accepts 1-512 printable ASCII characters and preserves the Bearer credential. `api` remains unchanged for calls without a grant. Neither method completes or bypasses verification.

## Verification

Unit tests cover encoded URL construction, deployment prefixes and rejected URL inputs. Management tests use local HTTP receivers to check query encoding, errors, empty responses and redirect refusal. Run `cargo test --manifest-path sdk/rust/Cargo.toml` from the repository root. These fixtures do not exercise a live provider or prove deployed authorization policy.
