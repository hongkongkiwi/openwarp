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

## Hosting

Docker is the supported self-host path (`docker compose up --build`:
server + Postgres + Redis). Set `OPENWARP_MASTER_KEY` (32 random bytes,
base64) and `OPENWARP_ENV=production` for anything real: production refuses
to start without an external master key, while development generates one and
stores it in the database with a warning. Cloudflare Workers cannot run this server
as-is (it needs OS sockets, threads and a local DB driver; Workers is a
wasm isolate runtime), so a Worker port would be a separate rewrite of
the storage and HTTP layers around the portable `openwarp-crypto` crate.

## CLI

```bash
openwarp login            # browser OAuth (PKCE, ephemeral loopback port), or: login --token <TOKEN>, or machine login with --client-id/--client-secret
openwarp init --app <APP_ID> --env <ENV_ID>   # writes .openwarp.json; later commands read it
openwarp secrets --env <ENV_ID>          # redacted list
openwarp secrets --env <ENV_ID> --show
openwarp export  --env <ENV_ID>
openwarp import  --env <ENV_ID> .env
openwarp run     --env <ENV_ID> -- ./your-app   # secrets injected as env vars
```

Access tokens are refreshed automatically from the saved refresh token when
one exists; `init` defaults remove the need to pass `--env` on every call.

## Sign-in and signups

Password sign-in is always available. Google and GitHub sign-in appear on the
login screen when `OPENWARP_GOOGLE_CLIENT_ID`/`_SECRET` or
`OPENWARP_GITHUB_CLIENT_ID`/`_SECRET` are set; an unconfigured provider returns
404 and is not advertised. Verified email addresses are required, and an account
that already has a password is never linked to a social identity silently.

Signups are open on a new instance. The instance owner (the first account) can
close them under Settings, or pin the policy with `OPENWARP_SIGNUPS=closed`.
With signups closed, new users join only through an invitation: an admin invites
an address, an existing account is added directly, a new address receives a
single-use link valid for seven days, and the invitee either sets a password or
signs in with a configured provider. See [docs/DEPLOY.md](docs/DEPLOY.md).

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
- OIDC SSO (authorization-code flow, JWKS-verified) identifies users by
  issuer plus subject, never by email: a first-time SSO login that matches an
  existing account is refused instead of linked, so an organisation cannot
  take over an account by configuring its own issuer. SCIM users and groups
  require `org_id` and admin rights in that organisation, and deactivation
  removes that organisation's membership only.
- TOTP MFA with recovery codes (also enforced on the OAuth consent flow, with
  per-address guess limits; changing an active enrolment requires the
  password), enforced IP allowlists covering `/api`, `/mcp` and `/scim`, login
  and registration rate limiting, and custom RBAC roles that are deny by
  default: a role only receives the permissions in its list, managed roles keep
  their documented breadth, and every read, write, delete, integration, lease,
  rotation, token and org-admin route checks one of them. Environment and
  application grant lists narrow the default, and an environment marked
  restricted admits only its members (or holders of an approved access
  request). Env-scoped service tokens cannot escape their environment over REST
  or MCP, cannot call SCIM, and cannot mint wider tokens. Machine identities
  (Universal Auth) issue 1-hour tokens and cannot mint longer-lived ones.
  Approval workflows, log streams, a rotation scheduler, allowlisted dynamic
  Postgres leases and a basic PKI round out the Phase + Infisical takeaways.
- OIDC issuer changes drop the stored client secret unless a new secret is
  supplied in the same request, so a secret is never sent to a different
  identity provider. OIDC states expire after ten minutes and the nonce is
  checked when the provider returns one.
- OAuth clients only receive scopes they registered; PKCE verifiers must be
  non-empty; MCP rejects any `Origin` that is not an exact match for the
  request host or the configured public URL.
- OAuth access tokens are scope-checked on every REST call (`secrets:read`
  for reads, `secrets:write` for mutations) and `/mcp` validates the token
  audience. The authorize page escapes all parameters and sets a
  restrictive Content-Security-Policy.
- `OPENWARP_ENV=production` refuses to start without `OPENWARP_MASTER_KEY`;
  development still generates one and stores it in the database, with a
  warning.
- Get an external crypto review before production use.

## Features (all unlocked)

See [docs/FEATURES.md](docs/FEATURES.md) for the full matrix and API reference.

## Development

```bash
cargo test --workspace     # crypto, DB and HTTP integration tests
cargo clippy --workspace --all-targets -- -D warnings
```

The integration suites spawn the real server on a private SQLite file:
`tests/security.rs` covers tenant isolation, SCIM scoping, OAuth scope and
audience, MFA on consent, token scoping, IP allowlists, HTML escaping, member
management and rate limiting; `tests/authorization.rs` covers custom-role
enforcement, admin gates, OIDC secret handling, the Postgres lease boundary,
scope escapes and account deactivation; `tests/accounts.rs` covers the signup
policy, invite provisioning and Google/GitHub sign-in against mock providers.
CI runs them on every push and pull request.
