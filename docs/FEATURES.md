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

## Takeaways from Phase + Infisical source review (implemented)

Reviewed `phasehq/console`, `phasehq/cli`, and `Infisical/infisical` against
OpenWarp. Deduplicated implement-now list, all shipped server-side:

- IP allowlists are now **enforced** by middleware (CIDR, fail-closed when
  set; `OPENWARP_TRUST_PROXY=1` to trust `X-Forwarded-For`), not just stored.
- Sealed secrets: type locked after save, values redacted in history as well
  as in list responses.
- SCIM and user lookup scoped to orgs the caller actually admins.
- Logout, 7-day session expiry, token list/revoke, env-scoped service
  tokens (a token scoped to one env gets 403 in any other).
- Custom RBAC matrix: `POST/GET /api/orgs/:id/roles` with permission lists
  (`secrets:write`, `secrets:delete`, `*`); custom-role members are checked
  on write/delete paths.
- TOTP MFA with one-time recovery codes: setup/verify, login challenge
  (`mfa_required` + 5-minute `mfa_token`), `POST /api/auth/mfa`.
- Lease renew, plus a rotation scheduler (30s tick) with per-key schedules
  (`/api/envs/:id/rotations`); E2E envs are skipped by the scheduler.
- Log streams with persisted delivery history and 3-attempt HMAC-signed
  retries (`/api/orgs/:id/log-streams`, `.../deliveries`).
- Extra sync kinds: Supabase, Nomad, Coolify, Cloudflare Pages.
- Machine identities with Universal Auth, secret-change proposals with
  admin approval, access requests, dynamic Postgres leases (real roles,
  dropped on revoke), and a basic PKI (CA, issue, revoke) came from the
  Infisical feature set.

Kept from OpenWarp where it already exceeds both: point-in-time recovery,
secret-change proposals, and Postgres dynamic roles are not Phase features.
Deferred by design: CLI parity (separate effort), Kubernetes operator,
SDKs, AWS-IAM dynamic secrets, Phase billing/licence code (never copied).

## Trigger.dev sync

Kind `trigger`, modelled directly on Trigger's env var REST API. Config:
`token` (PAT `tr_pat_...` or env secret key), `project_ref`, `target_env`
(`dev|staging|prod`) or `targets: [{project_ref, env, token}]` fan-out,
`env_map`, `mode: upsert|mirror|import`, `prefix`, `include_keys`,
`exclude_keys`, `base_url` (self-hosted), `dry_run`. Sync lists the remote
env, diffs, bulk-imports creates/updates, and in mirror mode only prunes
names this integration previously synced (tracked in
`integration_sync_state`). `POST /api/integrations/:id/test` verifies the
connection. Note: Trigger's REST create/import schema documents name/value
only, so dashboard-style secret marking cannot be set via API; sync results
say so explicitly when `mark_secret` is requested.

## OAuth 2.1, MCP and CLI

OpenWarp is its own OAuth 2.1 authorization server, shared by the CLI and
MCP: RFC 9728 protected-resource metadata
(`/.well-known/oauth-protected-resource`), RFC 8414 metadata
(`/.well-known/oauth-authorization-server`), RFC 7591 dynamic client
registration (`POST /oauth/register`), authorization code with mandatory
PKCE S256 (`GET /oauth/authorize`, consent page), `POST /oauth/token`
(refresh rotation: old refresh tokens die on use) and `/oauth/revoke`.
API auth accepts OAuth access tokens alongside sessions and service tokens.

MCP is served at `POST /mcp` (Streamable HTTP only; GET returns 405 on this
stateless server). Unauthenticated calls get 401 with
`WWW-Authenticate: Bearer resource_metadata=...`. Tools: `list_envs`,
`list_secrets`, `get_secret`, `search_secrets` (scope `secrets:read`) and
`set_secret`, `delete_secret`, `create_lease`, `sync_integration` (scope
`secrets:write`, RBAC still applies). Every tool call is audit-logged.
Resources: `openwarp://env/{env_id}`.

CLI (`openwarp` binary in the same monorepo) logs in three ways: browser
OAuth with PKCE and a loopback redirect (`login`), `login --token`, and
machine Universal Auth (`login --client-id/--client-secret`). Credentials
live in `~/.openwarp/config.json` (0600). Commands include `whoami`,
`logout`, `init`, `orgs/apps/envs`, `secrets`, `get`, `set`, `delete`,
`export --format dotenv|json|yaml|shell`, `import`, `run`,
`e2e-create/put/get/grant`, and `completion bash|zsh|fish|powershell`.
