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
| OIDC SSO / SCIM provisioning | Enterprise | **Full OIDC authorization-code flow per org**: `GET /api/auth/oidc/:org/start` (discovery, state), `GET /api/auth/oidc/callback` (code exchange, `id_token` verified against provider JWKS with RS/PS/ES signatures and iss/aud/exp/nonce checks, user auto-provisioned as org developer, session issued). Configure via `PUT /api/orgs/:id/settings` with `oidc_issuer, oidc_client_id, oidc_client_secret (encrypted at rest), oidc_redirect_uri`. Instance-level sign-in with any OIDC provider is configured by `OPENWARP_OIDC_*` (PKCE, optional client secret, discovery or explicit endpoints; see [configuration](CONFIGURATION.md)). SCIM 2.0: Users `POST/GET/PUT/PATCH/DELETE` (deactivation kills sessions and memberships, login returns 401) and Groups `POST/GET/PUT/PATCH/DELETE` mapped to Teams with member sync |
| External KMS | Enterprise | master key via `OPENWARP_MASTER_KEY` (BYO KMS/HSM wrapper point) |
| Licence checks / seat limits | n/a | **none, by design** |

## Integrations (`POST /api/envs/:id/integrations`, auto-sync on deploy, manual `POST /api/integrations/:id/sync`)

Config is stored encrypted under the env key. Secrets are pushed decrypted
(SSE mode), matching Phase SSE-enabled apps.

`github` (sealed-box via libsodium-compatible XSalsa20-Poly1305), `gitlab`,
`vercel`, `netlify`, `cloudflare` (Workers secrets), `heroku`, `render`,
`flyio`, `railway`, `digitalocean` (App Platform spec update),
`aws_secrets_manager` + `aws_parameter_store` (SigV4 signed, per-key or
one-JSON-secret modes), `gcp_secret_manager`, `azure_key_vault`,
`azure_app_configuration` (HMAC signed key-values), `scaleway_secret_manager`
(one opaque secret per key), `vultr`, `hetzner`, `linode` and `digitalocean_ssh` (account SSH public keys, from secrets of type `ssh_key`), `kubernetes`
(Opaque Secret), `hashicorp_vault`, `webhook` (generic JSON POST, optional
HMAC signature), `instabox`,
`boat`, `daytona`, `1password` (Connect; `onepassword` is accepted as an
alias), `dokploy`, `caprover`, `portainer`
(stack environment variables), `docker_swarm` (Docker Engine secrets),
`bitbucket`, `circleci`, `teamcity`, `travisci`, `terraform_cloud`, `qovery`,
`laravel_forge`, `openwarp` (instance-to-instance), `devin`,
`cloudflare_secrets_store`, `octopus_deploy`, `azure_devops`, `cursor`
(Cloud Agents environment or team secrets) and `ssh` (folders written to
files on a host).

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
Deferred by design: CLI parity (separate effort), a Kubernetes operator (the
Helm chart's External Secrets Operator bridge covers controller-driven delivery,
see [Kubernetes](KUBERNETES.md)), SDKs, AWS-IAM dynamic secrets, Phase
billing/licence code (never copied).

## Additional sync adapters (2026-11-06)

The following kinds share the `mode` (`upsert` or `mirror`), `dry_run`, `prefix`,
`include_keys` and `exclude_keys` options, and expose a connection test:

- `1password` uses a 1Password Connect server (`connect_url`, `token`,
  `vault_id`, optional `value_label`). Each key becomes an item whose title is
  the key and whose value sits in a concealed field. `onepassword` is accepted
  as an alias.
- `aws_secrets_manager` defaults to one secret per key. Setting `secret_id`
  switches to one JSON `SecretString`; `mapping` makes the choice explicit.
  `session_token`, `kms_key_id`, `endpoint` and `force_delete` are supported.
- `aws_parameter_store` writes one parameter per key under `path_prefix`, with
  `type`, `tier`, `kms_key_id` and `session_token` options.
- `dokploy` merges values into an application or compose env string and can
  redeploy after saving.
- `caprover` logs in with `password` (or accepts `token`) and updates an app's
  environment variables through API v2.
- `portainer` merges values into a Compose or Swarm stack's `Env` array without
  changing the stack file.
- `docker_swarm` writes Docker Swarm secrets through the Docker Engine API.
  Values are delete-and-recreate because Docker secrets are immutable.
- `bitbucket` writes repository Pipelines variables (Bearer or Basic auth).
- `circleci` writes project environment variables; existing names are recreated
  because CircleCI has no update call.
- `teamcity` writes project or build-type parameters (`project_locator` or
  `build_type_locator`).
- `travisci` writes repository environment variables.
- `terraform_cloud` writes workspace variables in the configured `category`
  (`env` by default) with the `sensitive` flag.
- `qovery` writes environment variables at the configured `scope`.
- `laravel_forge` merges the site `.env` file and writes it back.
- `openwarp` pushes to another OpenWarp environment and can mirror deletions.
- `devin` writes organization-level key-value secrets.
- `cloudflare_secrets_store` writes one store secret per key with `scopes`.
- `octopus_deploy` updates the project variable collection.
- `azure_devops` updates a pipeline variable group.
- `cursor` writes Cloud Agents environment or team secrets
  (`runtime_secret` or `environment_variable`).

Shared behavioural options:

- `name_template` supports `{{secretKey}}` and `{{environment}}`; `prefix` also
  accepts `{{environment}}`.
- `auto_sync: false` skips the integration on deploy, rotation, proposal,
  delete, restore and point-in-time restore; manual Sync still runs it.
- `initial_sync` accepts `overwrite` (default), `import_local` (keep local
  values) or `import_remote` (remote values win). Import runs on the first
  stateful sync and is available for AWS Secrets Manager, AWS Parameter Store,
  1Password, Dokploy, CapRover, Portainer, Bitbucket, TeamCity, Travis CI,
  Terraform Cloud, Qovery, Laravel Forge, Octopus Deploy, Azure DevOps and
  OpenWarp. Adapters that never return values reject import explicitly.
- AWS integrations accept `role_arn` plus optional `sts_endpoint`; the adapter
  assumes the role and signs with the temporary credentials.

Kamal has no server API or central secret store, so there is no `kamal` adapter.
Use `openwarp export --format dotenv` or `openwarp run -- kamal deploy` to feed
`.kamal/secrets` at deploy time.

Cursor Cloud Agents is supported because it documents environment and team
secret endpoints. Grok Bot Vault and ChatGPT/Codex cloud environments document
environment variables and secrets as UI settings, not as a public API. Keeper
requires Commander in Service Mode. Pandacode's other providers are machine
lifecycle APIs that accept environment variables or SSH keys only at creation;
they are not secret-sync destinations. An SSH host can still receive files
through the `ssh` adapter, which writes folders to env files.

Still pending from the wider Infisical-style list: Spacelift, OCI Vault, OVH,
Northflank, Rundeck, Cloud 66 and Humanitec. Each needs its own auth or API
contract before it can be implemented without guessing.

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
`export --format dotenv|json|yaml|shell [--base]`, `import`, `run`,
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

## Platform pass (2026-11-06)

### Email providers and templates

`OPENWARP_EMAIL_PROVIDER` selects `smtp`, `resend`, `sendgrid`, `twilio`
(alias for SendGrid), `mailgun`, `postmark`, `cloudflare`, `webhook` or `log`.
Without an explicit setting the provider is inferred from the credentials that
are present. SMTP supports `none`, `starttls` (default) and `implicit` TLS.
Cloudflare is an Email Worker relay, because Email Routing has no transactional
send API. Built-in verify, reset, invite and test templates are used unless
`OPENWARP_EMAIL_TEMPLATES_DIR` provides `<kind>.subject.txt`, `<kind>.txt` and
`<kind>.html` with `{{variable}}` placeholders.

`POST /api/instance/email-test {to}` lets the instance owner verify delivery.
Mail failures are logged and never expose the message body or credentials.

### Migrations, pooling and master-key rotation

`db.rs` records a baseline and numbered migrations in `schema_migrations`;
additive column errors that mean "already applied" are recognised, anything
else aborts boot. Postgres uses an `r2d2` connection pool sized by
`OPENWARP_PG_POOL_SIZE` (default 8) instead of one serialized client and a
thread per query. The storage API remains synchronous; a fully async database
rewrite is still outstanding.

`POST /api/instance/rotate-master {new_key}` is instance-owner only. It
preflights every master-wrapped value, re-wraps environment keys, OIDC and TOTP
secrets, CA private keys and log stream secrets, updates the generated master
key row, then switches the in-process key. A failure anywhere in the preflight
leaves the old key in place. Operators using `OPENWARP_MASTER_KEY` must update
the environment and restart with the new key.

### Token scopes, pagination, teams and scanning

Service tokens accept `scopes: "secrets:read"` and/or `"secrets:write"` and
`expires_in`. A read-only token is rejected on mutations by the scope
middleware, and `last_used_at` is recorded at most once a minute.
`GET /api/envs/:id/secrets?limit=&offset=` returns `total`, `limit` and
`offset`; audit listing accepts the same paging parameters.
Teams now have member management and `team_env_grants`: a restricted
environment admits members of a team granted that environment.
`GET /api/envs/:id/scan` reports high-confidence AWS, GitHub, Slack, Stripe,
Google and private-key patterns without returning values; deploy responses
include `scan_findings` for the submitted secrets.

### PKI, AWS leases and HA

`GET /api/pki/cas/:id/crl` returns a signed PEM CRL containing every revoked
certificate, with the issuer reconstructed from the stored serial.
Dynamic leases support `type: "aws_iam"`: OpenWarp calls STS AssumeRole with
the supplied admin credentials, returns temporary credentials, and never stores
the admin secret. Postgres lease host allowlisting remains in force.

`type: "openrouter"`, `"resend"` and `"openai"` mint a child key from a parent
management key and delete that child when the lease is revoked. OpenRouter takes
`management_key` (optional `limit`, `limit_reset`, `workspace_id`) and sets the
child `expires_at` from the lease TTL. Resend takes `api_key` and defaults the
child to `sending_access`. OpenAI takes `admin_key`, `project_id` and
`service_account_id`, and sets `expires_in_seconds` from the TTL. Hugging Face
takes `token`, `org` and `service_account_id` (optional `permissions`) and
creates a fine-grained service-account token; revoke deletes that token.

The same lease covers the inference providers whose APIs both mint and delete a
child credential:

| type | parent credential | also required | revoke |
| --- | --- | --- | --- |
| `fireworks` | `api_key` | `account_id`, `user_id` | posts the key id to `apiKeys:delete` |
| `mistral` | `admin_key` (Enterprise Admin API) | `workspace_id` | deletes `/v1/admin/api-keys/{id}` |
| `perplexity` | `api_key` | | posts the child token to `/revoke_auth_token` |
| `xai` | `management_key` | `team_id` | deletes `/auth/api-keys/{id}` |
| `gemini` | `access_token` | `project` | deletes the API Keys resource |
| `cloudflare` | `api_token` | `policies` | deletes `/user/tokens/{id}` |
| `deepgram` | `api_key` | `project_id` | deletes `/v1/projects/{project}/keys/{id}` |
| `elevenlabs` | `api_key` | `service_account_id` | deletes the service-account key |
| `deepinfra` | `api_key` | | deletes `/v1/api-tokens/id/{id}` |
| `baseten` | `api_key` | | deletes `/v1/api_keys/{prefix}` |
| `fal` | `api_key` | | deletes `/v1/keys/{id}` |
| `speechmatics` | `management_token` | | deletes `/v1/api-keys/{id}` |
| `chutes` | `api_key` | | deletes `/api_keys/{id}` |

Fireworks, Mistral, Gemini, Cloudflare, Deepgram and Baseten set a remote expiry
from the lease TTL. Baseten personal keys cannot outlive 90 days, so a longer TTL
is shortened. Speechmatics mints a permanent project key when `project_id` is set
and a temporary key (60 seconds to 24 hours) otherwise. Perplexity, xAI,
ElevenLabs, DeepInfra, fal and Chutes do not expire a key themselves, so those children
stay usable until revoked. Gemini's create call returns a long-running operation; the lease
fails unless the key is already in the response. Cloudflare `policies` are sent
as given, so the parent token's `API Tokens Write` permission is what bounds
them. xAI defaults the child to every model and endpoint the team can use, and
accepts `qps`, `qpm` and `tpm`. ElevenLabs defaults `permissions` to `"all"`.

The parent credential is encrypted on the lease so revoke can authenticate; the
response returns only the child secret. A failed remote delete leaves the lease
active. Expiry does not revoke the remote key by itself: call revoke, or rely
on the provider expiry where one was set at creation. Resend keys have no
remote expiry. Anthropic's Admin API can list and deactivate keys but has no
documented create call, so it is not a lease provider. Groq, Together, Cohere,
DeepSeek, Cerebras, SambaNova, Voyage and AssemblyAI only mint keys from their
dashboards, so they are not either. None of these providers publish an OAuth
flow that yields an API credential, so there is no login-based fallback.
Background jobs (rotation and cleanup) use an `instance_leases` row so one
replica runs them; the HTTP layer itself is stateless and can run behind a
load balancer with shared Postgres and optional Redis.

`GET /api/live` upgrades to a WebSocket. The caller authenticates with the same
session cookie or bearer token as the rest of the API, and each frame is an
audit event (organisation, application, environment, action, detail, timestamp)
for an organisation the caller belongs to. Secret values are not included. An
environment event is dropped unless `require_env` admits the caller. Every
replica polls the shared `live_events` table, so a socket held by one replica
sees a change committed by another within about a second. Rows older than an
hour are deleted by the background loop. Reconnect with `?since=<id>` using the
last id received: the server sends up to 500 matching events from the past hour
before resuming the live stream, and skips any the catch-up already delivered.
The server sends a ping every 30 seconds, which keeps the socket inside
Cloudflare's idle timeout. The five-minute handler deadline does not apply to
this route.

### Clients and deployment

- TypeScript SDK: `sdk/typescript`
- Python SDK: `sdk/python`
- Go SDK: `sdk/go`
- Rust SDK: `sdk/rust`
- Terraform provider scaffold: `terraform-provider-openwarp`
- Helm chart: `deploy/helm/openwarp` (two replicas, probes, ingress, PDB)
- Export action: `action/` (`openwarp` environment to dotenv or JSON)

The Python, Go, Helm and action deliverables have runnable local tests. The
TypeScript, Rust and Terraform sources are not compiled or integration-tested
in this repository.

### Still not implemented

SAML 2.0 SSO, an OCSP responder, provider-specific secret rotation (the generic
rotation webhook is not shipped), and a fully asynchronous Postgres API. Do not
treat CRL support as an OCSP replacement.

## Account lifecycle (2026-11-06)

- Ownership transfer is `POST /api/orgs/:id/transfer {user_id}`. The target must
  already be a member with an active, verified account; the caller becomes an
  admin. The console's Members table exposes the same transfer, role changes and
  member removal.
- `DELETE /api/me` deletes the calling account. It requires a signed-in console
  session, so an API key, service token or OAuth token cannot delete the account
  that issued it. A user who owns any workspace gets `409` with the workspace
  list until ownership is transferred; the instance owner is refused for the
  same reason.
- Live credentials turn the request into a `409` warning with
  `confirmation_required`, `api_keys` and `oauth_sessions` counts; repeat with
  `DELETE /api/me?confirm=true` to proceed. The delete revokes sessions, OAuth
  access and refresh tokens, service tokens the user created, environment keys,
  overrides and identity bindings. Organisation history (audit, proposals,
  access requests) remains.
- OAuth consent with email and password now refuses an unverified account,
  matching the console sign-in gate. Verified accounts continue through the
  normal authorization-code flow.
