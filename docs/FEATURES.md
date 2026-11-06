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
True E2E envs (`POST /api/apps/:id/envs/e2e`) are also implemented: the CLI
generates the env key locally and sends only the wrapped form (`wrapped_key`,
wrapped to the creator's X25519 public key), so the server never sees the
key. It stores only ciphertext it cannot decrypt. Clients that omit
`wrapped_key` get a server-generated key instead and the response carries
`server_generated: true`, which is a compatibility path, not E2E. Grant access with `POST /api/envs/:id/e2e/grant` where the
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

## Sign-in methods and second factors

The instance owner chooses which methods the server offers under Settings:
email and password, Google, GitHub and organisation OIDC can each be turned
off, as long as one method stays on. `OPENWARP_AUTH_PROVIDERS` pins the list and
wins over the console. Google and GitHub need client credentials before they
can be enabled; OIDC counts once an organisation has an issuer. Turning
password off also blocks password registration, password reset and the OAuth
consent password form.

Each account can add any combination of second factors:

- TOTP authenticator app with recovery codes (`/api/me/totp/setup`, verify,
  `DELETE /api/me/totp`).
- WebAuthn passkeys (`/api/me/passkeys/start|finish`, list in `/api/me/mfa`,
  `DELETE /api/me/passkeys/:id`). Registration and assertions are verified by
  `webauthn-rs` with user verification required. Challenges live server-side
  for five minutes, credential IDs are unique across the instance, and a
  stalled signature counter rejects the credential.
- Emailed six-digit codes (`/api/me/mfa/email/...`), valid for ten minutes,
  single use, five attempts. Enrolment and delivery fail closed when
  `OPENWARP_EMAIL_WEBHOOK` is unset.

Once a factor is enabled, every sign-in path asks for it: password, Google,
GitHub, OIDC and the OAuth consent form. `POST /api/auth/mfa` accepts a TOTP,
recovery or emailed code; `POST /api/auth/mfa/passkey/start|finish` completes a
passkey assertion. Adding a factor to an account that already has one, and
removing any factor, requires the current password when the user knows one.
Recovery codes are shown once when the first factor is enrolled and can be
replaced with `POST /api/me/mfa/recovery-codes`. A completed password reset
asks for a configured factor too; it does not issue a session on its own.
Re-enrolling TOTP keeps the previous secret active until the new one is
verified, so an abandoned setup never leaves the account without a factor.

Passkeys need a secure browser context: HTTPS, or localhost in development.
`OPENWARP_PUBLIC_URL` supplies the relying-party origin; `OPENWARP_RP_ID` and
`OPENWARP_RP_ORIGIN` override it when a proxy or split origin requires that.

## Encryption modes and key custody

Environments choose one of three modes:

- `sse` (managed): the server unwraps an environment key and decrypts for the
  API and integrations. With `OPENWARP_KMS_URL`, the root and each environment
  key are wrapped by an external KMS/HSM; without it, `OPENWARP_MASTER_KEY` or a
  generated key in `meta` is the root.
- `delegated`: the client generates the environment key, wraps it to itself and
  to a customer-run sync runner, and writes ciphertext. The server queues sync
  jobs; the runner decrypts in its own process and pushes to the provider. The
  server cannot read the environment or the provider config.
- `e2e`: client-held keys without a runner grant. Server-side integrations are
  unavailable.

Secret ciphertext written by the server uses `ow2` AEAD framing bound to the
environment, secret and field, so a value cannot be moved between records.
Legacy ciphertext remains readable. `POST /api/instance/rewrap` re-wraps every
environment key under the current KMS key ID.

Runner identities are created per organisation
(`POST/GET /api/orgs/:id/runners`, `DELETE /api/orgs/:id/runners/:rid`). The
token and private key are shown once. The runner polls
`/api/runner/jobs` and reports to `/api/runner/jobs/:id/result`; a claimed job
times out after ten minutes. Integration configuration for a delegated
environment is sealed to the runner's X25519 key, not to the server.

Removing a member from a client-encrypted environment sets a rekey flag.
`openwarp e2e rekey --env ENV_ID` generates a new environment key, re-encrypts
every secret, and rewraps it to the remaining users and the runner. Old
versions are replaced because they cannot be read after the rotation.

The [security model](SECURITY.md) states what each mode does and does not
protect against, including the remaining server-sees-passwords and
server-served-client limits.

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

## Instabox org Secrets

Kind `instabox` syncs environment secrets into an Instabox organisation's
Secrets over its REST API (`/v1/orgs/{org}/secrets`). Config: `api_key` (an
`ibk_` key, or `token`), `org`, `delivery` (`proxy` default, or `env`),
`hosts` (exact hostnames the Instabox proxy may substitute the value into;
proxy delivery only; required unless `allow_all_hosts: true` is set), `mode`
(`upsert` default, or `mirror`), `prefix`,
`include_keys`, `exclude_keys`, `base_url` for self-hosted, and `dry_run`.

Sync lists remote metadata first, imports every desired name in one atomic
`/import` call, and in mirror mode deletes only names this integration
previously managed, tracked in `integration_sync_state`. Dry-run performs no
writes and reports would-create and would-replace counts. Instabox never
returns values, so sync cannot diff by value; it reports what it sent. Names
are validated against Instabox's `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, and
values are checked for size and, in proxy mode, for CR or LF. Deploying an
environment triggers the same path as other integrations.
`POST /api/integrations/:id/test` verifies the key and org.

## Boat sandbox environments

Kind `boat` writes environment variables into a Boat sandbox environment
(`https://boat.dev/api/v1`). Config: `api_key` (a `boat_` key), `environment`
(name or UUID, default `base`), `org` (the shared wallet for team
environments), `mode` (`upsert` or `mirror`), `prefix`, `include_keys`,
`exclude_keys`, `upgrade` (calls `POST /environments/{id}/upgrade` after
syncing so existing sandboxes pick up the new version), `base_url`, and
`dry_run`. Sync reads `envContents` from `GET /environments`, sets each
variable with `PUT /environments/{id}/vars/{KEY}`, and in mirror mode deletes
only previously managed names. The `org` selector is sent on mutations too,
as Boat requires for shared environments. Names must match
`^[A-Za-z_][A-Za-z0-9_]*$`.
Boat only delivers variables to sandboxes created or upgraded after the
change, so set `upgrade` when existing sandboxes must see the new values.

## Daytona vault secrets

Kind `daytona` writes to Daytona's organisation vault
(`https://app.daytona.io/api`). Config: `api_key`, `organization_id` (sent as
`X-Daytona-Organization-ID`; required when the key is a JWT), `hosts` (allowed
outbound hosts stored on each secret), `sandbox` (optional id or name; when
set, sync mounts every managed secret into that sandbox with
`PUT /sandbox/{id}/secrets`), `mode`, `prefix`, `include_keys`,
`exclude_keys`, `base_url`, and `dry_run`. Listing uses
`GET /secret/paginated` and falls back to the legacy `GET /secret`. Daytona
never returns values, so sync creates missing names with `POST /secret` and
patches existing ones with `PATCH /secret/{id}`. Mirror deletes only
previously managed names. Daytona has no API to change environment variables
on an existing sandbox after creation; use vault secrets plus the mount, or
create the sandbox with `env` and replace it.

## Hardening pass (2026-11-06)

- SCIM requires `?org_id=<org>` and owner or admin rights in that org. User
  listing returns only that org's members, user updates reject non-members,
  group operations verify the group belongs to the org, and deactivation
  removes that membership only.
- OIDC binds accounts by issuer plus subject in `oidc_subjects`. A first SSO
  login whose email already exists is refused instead of linked, closing the
  attacker-configured-issuer takeover.
- OAuth consent enforces TOTP when the account has it enabled, rejects
  deactivated accounts, rate-limits password attempts, escapes every
  parameter and serves a restrictive Content-Security-Policy.
- OAuth access tokens are scope-checked on REST (`secrets:read` for reads,
  `secrets:write` for mutations) and `/mcp` checks the token audience.
- Environment-scoped service tokens are rejected over MCP for other
  environments and cannot mint new tokens.
- The IP allowlist covers `/api`, `/mcp` and `/scim`, not just `/api`.
- Login and consent attempts are limited to five failures per 15 minutes per
  IP and email. Session cookies gain `Secure` when the public URL is HTTPS.
- Machine identities cannot hold the owner role, only owners can create
  admin identities, and custom-role members cannot create identities.
- MCP write tools honour `secrets:write`, `secrets:delete` and
  `secrets:write` on rotation and leases, matching the REST checks.
- Trigger sync fails when any target fails, and validates
  `dev|staging|prod`.
- New endpoints: `GET /api/orgs/:id/members`,
  `DELETE /api/orgs/:id/members/:uid`, `PATCH|DELETE /api/apps/:id`,
  `PATCH /api/envs/:id`.
- `OPENWARP_ENV=production` refuses to start without `OPENWARP_MASTER_KEY`.
- Committed HTTP integration suite in `crates/server/tests/security.rs` and
  CI in `.github/workflows/ci.yml`.

## Second hardening and feature pass (2026-11-06)

- Custom roles are deny-by-default: every route checks `secrets:read`,
  `secrets:write`, `secrets:delete`, `integrations:write`, `leases:write`,
  `rotations:write`, `proposals:write`, `tokens:create` or `org:admin`.
  Managed `developer` keeps the documented breadth; `owner` and `admin` pass all.
- Organisation settings are admin-only, have a `GET` endpoint, validate IP
  CIDRs, and never return the OIDC client secret. A partial update cannot wipe
  OIDC; changing the issuer without a new secret clears the stale secret.
  `oidc_auto_provision` and `oidc_allowed_domains` gate first-time SSO joins.
- Rate limits live in the database, so a restart or a second replica keeps the
  budget. Registration, login, consent, MFA and universal auth all limit.
  TOTP codes cannot be replayed and MFA challenges are attempt-capped.
- Deactivated accounts and deleted identities lose sessions, OAuth tokens and
  PATs immediately. Machine tokens cannot mint long-lived service tokens.
- Integration sync excludes sealed secrets and personal overrides: only shared
  base values reach a remote platform. Coolify and Vercel now fail closed.
- PITR restores the whole environment at a timestamp: later secrets are
  tombstoned, deleted ones return, and key/value/comment/type are restored.
- Scheduled rotation claims its slot atomically, honours the stored path, skips
  sealed secrets with an audit entry, and pushes the new value to integrations.
  Manual rotation does the same.
- `DELETE /api/envs/:id` and `DELETE /api/apps/:id` remove every child row,
  including integration sync state, environment grants and app members.
- Log streams sign `t=<unix>,v1=<hex HMAC-SHA256(t.payload)>` in
  `X-OpenWarp-Signature` and send `X-OpenWarp-Timestamp`; delivery is bounded.
- New settings and lifecycle endpoints: `PATCH /api/orgs/:id`,
  `POST /api/orgs/:id/leave`, `POST /api/orgs/:id/transfer`,
  `PATCH /api/orgs/:id/members/:uid`, `GET|PUT /api/orgs/:id/settings`,
  `POST|DELETE /api/integrations/:id`, `PATCH|DELETE /api/integrations/:id`,
  `GET|DELETE /api/envs/:id/e2e/grants`,
  `POST /api/orgs/:id/identities/:iid/rotate`,
  `DELETE /api/orgs/:id/identities/:iid`,
  `POST /api/envs/:id/clone`, `GET /api/envs/:id/compare`,
  `GET /scim/v2/ServiceProviderConfig|ResourceTypes|Schemas`.
- Service tokens accept `expires_in` seconds. SCIM Users and Groups support
  `startIndex`, `count` and a simple `userName`/`displayName eq "..."` filter.
- Per-environment policy: `PUT /api/envs/:id/policy {restricted,require_approval}`.
  `restricted` narrows membership to explicit env/app grants; `require_approval`
  blocks direct developer deploys and forces the proposal flow. An approved
  access request no longer makes an environment exclusive by itself.
- `/health` checks the database and returns 503 when it cannot query. Request
  bodies are capped at 8 MiB, handlers time out after five minutes, and the
  server drains connections on SIGTERM/SIGINT. `/metrics` is token-gated.
- Lockbox links now resolve to a real one-time viewer page. E2E environments
  show a dedicated decrypt panel in the console, and grants can be revoked.
- Console sessions use the HttpOnly cookie rather than localStorage, with a
  restrictive CSP; secret keys are character-validated and JS-string-escaped.
- The CLI stores credentials in the OS keyring by default and exports or runs
  multi-line values without splitting them on newlines.
