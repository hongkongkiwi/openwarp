# Feature matrix (Phase clone, everything unlocked)

| Phase feature | Tier in Phase | OpenWarp |
|---|---|---|
| Organisations, members, invite | Free | unlimited, roles owner/admin/developer + custom role strings |
| Apps + readme | Free | yes |
| Environments | 3 / 10 / unlimited | **unlimited custom envs**, name `^[a-zA-Z0-9-_]{1,32}$` |
| Secrets: secret/sealed/config types | Free | yes; sealed never read back |
| Folders/paths, tags, comments | Free | yes (key unique per env+path) |
| Versioning, history diff, one-click restore | Free | `GET /api/secrets/:id/history`, `POST .../restore/:ver` |
| Secret referencing `${KEY}`, `${/path/KEY}` | Free | resolved server-side, 5-deep |
| Personal overrides | Free | `POST /api/secrets/:id/override`, merged on read |
| Global search | Free | `GET /api/search?q=` across orgs/apps/envs |
| Lockbox one-time sharing | Free | `POST /api/lockbox` (key in URL fragment), one view, 24h |
| `.env` import/export | Free | `POST /api/envs/:id/import`, `GET .../export` |
| Service accounts / PATs | Free (paid seats upstream) | `POST /api/apps/:id/tokens`, Bearer auth everywhere |
| Teams | Pro | `GET/POST /api/orgs/:id/teams` |
| Custom RBAC | Pro | free-form role column, admin gates on destructive ops |
| Network policies | Pro | `PUT /api/orgs/:id/settings {ip_allowlist}` stored per org |
| Point-in-time recovery | Pro | `POST /api/envs/:id/restore-point {timestamp}` |
| Automated rotation | Pro | `POST /api/envs/:id/rotate {key}` (new random or given value) |
| Audit logs + forwarding | Pro/Ent | per-org audit table, webhook forwarding via settings |
| Dynamic secrets | Enterprise | TTL leases `GET/POST /api/envs/:id/dynamic` (1h default) |
| OIDC SSO / SCIM provisioning | Enterprise | **Full OIDC authorization-code flow per org**: `GET /api/auth/oidc/:org/start` (discovery, state), `GET /api/auth/oidc/callback` (code exchange, RS256 `id_token` verified against provider JWKS, iss/aud/exp checked, user auto-provisioned as org developer, session issued). Configure via `PUT /api/orgs/:id/settings` with `oidc_issuer, oidc_client_id, oidc_client_secret (encrypted at rest), oidc_redirect_uri`. SCIM 2.0: Users `POST/GET/PUT/PATCH/DELETE` (deactivation kills sessions and memberships, login returns 401) and Groups `POST/GET/PUT/PATCH/DELETE` mapped to Teams with member sync |
| External KMS | Enterprise | master key via `OPENWARP_MASTER_KEY` (BYO KMS/HSM wrapper point) |
| Licence checks / seat limits | n/a | **none, by design** |

## Integrations (`POST /api/envs/:id/integrations`, auto-sync on deploy, manual `POST /api/integrations/:id/sync`)

Config is stored encrypted under the env key. Secrets are pushed decrypted
(SSE mode), matching Phase SSE-enabled apps.

`github` (sealed-box via libsodium-compatible XSalsa20-Poly1305), `gitlab`,
`vercel`, `netlify`, `cloudflare` (Workers secrets), `heroku`, `render`,
`flyio`, `railway`, `digitalocean` (App Platform spec update),
`aws_secrets_manager` + `aws_parameter_store` (SigV4 signed),
`gcp_secret_manager`, `azure_key_vault`, `kubernetes` (Opaque Secret),
`hashicorp_vault`, `webhook` (generic JSON POST).

Each kind takes `token` plus target ids in `config`, e.g.
`{"kind":"gitlab","config":{"token":"glpat-...","project_id":"42"}}`.

## End-to-end encryption mode

SSE mode is the default (server decrypts for sync/CLI, ciphertext at rest).
True E2E envs (`POST /api/apps/:id/envs/e2e`) are also implemented: the env
key is generated client-side of the trust boundary, wrapped to each member's
X25519 public key (`env_keys` table), and the server only stores ciphertext
it cannot decrypt. Grant access with `POST /api/envs/:id/e2e/grant` where the
*wrapped key is produced by the grantor's client*, never by the server.

- CLI: `openwarp e2e-create|e2e-put|e2e-get|e2e-grant` (keys from `OPENWARP_PRIVKEY`, your recovery kit).
- Browser: the console's E2E panel decrypts in-page with the pure-JS
  X25519 + XChaCha20-Poly1305 implementation in `crates/server/src/e2e.js`;
  the recovery kit never leaves the page. JS and Rust implementations are
  cross-tested both directions, including tamper rejection.

## Storage

`DATABASE_URL=sqlite://file.db` (default, testing) or
`postgres://...` (production). One portable SQL dialect layer translates
`?` placeholders to `$n` for Postgres. `REDIS_URL` optionally caches session lookups (1h TTL, verified against a Redis-protocol server: SETEX on first auth, GET hits after); absent Redis, sessions live only in the DB.
