# OpenWarp

Clean-room Rust clone of the Phase secrets platform (behaviour modelled on the
public [Phase Console docs](https://docs.phase.dev/console)). **No tiers, no
licence checks, no seat/env limits, no telemetry.** All Pro/Enterprise-tier
features are included for everyone.

This is an independent reimplementation. No Phase enterprise (`ee/`) code,
assets or branding are used.

## Run

```bash
# SQLite (zero config, great for testing)
DATABASE_URL=sqlite://openwarp.db ADDR=127.0.0.1:8080 cargo run -p openwarp-server
# Postgres + optional Redis session cache
DATABASE_URL=postgres://user:pass@host:5432/openwarp REDIS_URL=redis://127.0.0.1:6379 cargo run -p openwarp-server
# or
docker compose up --build   # server + Postgres 17 + Redis 7
```

Open http://127.0.0.1:8080 and register. Save the **recovery kit** returned at
registration offline: it is your X25519 private key.

## CLI

```bash
export OPENWARP_HOST=http://127.0.0.1:8080 OPENWARP_TOKEN=<token-from-UI-or-login>
openwarp secrets --env <ENV_ID>          # redacted list
openwarp secrets --env <ENV_ID> --show
openwarp export  --env <ENV_ID>
openwarp import  --env <ENV_ID> .env
openwarp run     --env <ENV_ID> -- ./your-app   # secrets injected as env vars
```

## Security model

- Crypto mirrors Phase's documented construction: ephemeral X25519 key
  exchange + XChaCha20-Poly1305 AEAD (`Keph || nonce || ct`), Argon2id
  password wrapping of user private keys, SHA-256 token hashing.
- Secrets are stored only as ciphertext (`key_enc`, `value_enc`, `comment_enc`)
  under a per-environment data key; that key is wrapped by the server master
  key (`OPENWARP_MASTER_KEY`, or a generated key persisted in the `meta`
  table). This is Phase's *SSE* mode. The `openwarp-crypto` crate provides the
  full E2E primitives (encrypt-to-public-key, sealed box) used for Lockbox and
  GitHub sync; browser-side E2E decryption is future work, so treat the server
  as trusted for plaintext in transit, exactly like an SSE-enabled Phase app.
- `sealed` secrets are never returned by the API after deploy.
- True E2E environments are available alongside SSE: in E2E envs the server
  stores only ciphertext and wrapped env keys it cannot decrypt; the CLI and
  the browser console (pure-JS X25519/XChaCha20-Poly1305) decrypt locally.
- OIDC SSO (authorization-code flow, JWKS-verified) and SCIM provisioning
  (users + groups) are wired per organisation.
- Get an external crypto review before production use.

## Features (all unlocked)

See [docs/FEATURES.md](docs/FEATURES.md) for the full matrix and API reference.

## Development

```bash
cargo test --workspace     # crypto + DB tests
cargo clippy --workspace -- -D warnings
```
