# Configuration reference

Configure the server through its process environment. Workspace policies and integration configuration are stored through the console/API instead. CLI variables affect the client process and are listed separately below.

For Compose, explicitly add variables to `services.server.environment` or an `env_file`. Host exports and Compose's interpolation `.env` are not automatically forwarded. See [deployment](DEPLOY.md#pass-deployment-settings-into-the-container).

## Server and storage

| Variable | Default | Behavior |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite://openwarp.db` | SQLite file, PostgreSQL connection URL, or MySQL/MariaDB URL (`mysql://`, `mariadb://`) |
| `ADDR` | `0.0.0.0:8080` | Listen IP and port; use loopback for private local development |
| `OPENWARP_ENV` | Unset | `production`, case-insensitive, requires an external master key or a configured KMS bridge and activates production-specific checks |
| `OPENWARP_MASTER_KEY` | Generated/stored in development without KMS | Base64 representing exactly 32 bytes; preserve the original value for an existing database |
| `OPENWARP_KMS_URL` | Unset | Native server HTTP(S) bridge for root/key wrapping; permits production auto-unseal without a plaintext master-key variable. `http://` is accepted, so use HTTPS, loopback or a protected private network |
| `OPENWARP_KMS_TOKEN` | Unset | Optional bearer credential for the configured KMS bridge |
| `OPENWARP_KMS_KEY_ID` | `primary` | Bridge key identifier stored in wrapped payloads; preserve access to previous identifiers |
| `REDIS_URL` | Unset | Optional session cache with the default `redis-cache` build feature |
| `OPENWARP_PUBLIC_URL` | Derived from request context where needed | Canonical public origin for issuer metadata, redirects, and links; configure explicitly in deployed instances |
| `OPENWARP_PG_POOL_SIZE` | `8` | Postgres connections per process, clamped to 1..64. Multiply by the replica count before sizing the database |
| `OPENWARP_MYSQL_POOL_SIZE` | `8` | MySQL/MariaDB connections per process, clamped to 1..64 |
| `OPENWARP_SECURE_COOKIES` | Unset | `1` forces Secure cookies; an HTTPS public URL also enables the flag |
| `OPENWARP_REGION` | `global` | Jurisdiction label for this deployment, 1 to 32 characters of `a-z`, `0-9` or `-`. It describes the data in this deployment's own database and is not stored on tenant rows. An empty value is treated as unset |
| `OPENWARP_REGIONS` | Unset | Optional `label=origin` list such as `global=https://global.example.com,eu=https://eu.example.com`. The sign-in card offers a hand-off to these origins. Origins must be HTTPS, or HTTP on a loopback host, carry no credentials, query or path, are published to the console in canonical `scheme://host[:port]` form, and startup fails unless the list names this deployment's own region |
| `OPENWARP_METRICS_TOKEN` | Unset | Enables `/metrics`; callers must supply this bearer token |

The SQLite path is relative to the process working directory unless absolute, for example `sqlite:///var/lib/openwarp/openwarp.db`. Create the parent directory and grant the service account access.

The PostgreSQL adapter uses `NoTls`. A connection string does not add TLS support to that adapter. Use an isolated network or separately configured secure transport.

The MySQL/MariaDB adapter targets MySQL 8.0.13+ or MariaDB 10.6+. It creates tables with `utf8mb4_bin` collation so hash and token lookups stay case-sensitive, and it rewrites keyed `TEXT` columns to `VARCHAR(255)`. TLS is used only when the URL asks for it with `require_ssl=true`; host identity is then verified unless you also pass `verify_identity=false`. Without `require_ssl` the connection is plaintext.

That storage adapter is native-only: a Workers deployment keeps its data in the Durable Object. MySQL and MariaDB are still available there as dynamic lease targets, through a protocol client built into the Worker.

Generate a master key only for a new database:

```bash
openssl rand -base64 32
```

Store the result securely. A replacement value does not rotate existing ciphertext. Development promotion must preserve the database's existing generated key.

Startup root precedence is explicit: `OPENWARP_MASTER_KEY` when set; otherwise, with `OPENWARP_KMS_URL` set, the KMS-wrapped `meta.kms_root` (on first boot it wraps an existing plaintext `meta.master`, or mints a root when none exists); outside production, a stored plaintext `meta.master` or a generated development key stored in the database. Production without an external master key or configured KMS bridge aborts before either development fallback. If a plaintext `meta.master` and the unwrapped KMS root disagree, startup stops and neither row is deleted, because either deletion would lose key material. Online instance-root rotation is limited to single-process SQLite; PostgreSQL and MySQL/MariaDB return a conflict and need a coordinated offline procedure.

The KMS bridge URL may be plain HTTP. In that case wrap requests and unwrap responses carry plaintext root or environment keys over that unencrypted connection, and the bridge has no egress allowlist of its own. Use HTTPS, a loopback listener, or a protected private network, and give `OPENWARP_KMS_TOKEN` only to the adapter that terminates that trust boundary.

## Registration and email

| Variable | Default | Behavior |
| --- | --- | --- |
| `OPENWARP_SIGNUPS` | Stored instance policy; initially open | `open` or `closed` pins the policy and overrides the console toggle |
| `OPENWARP_WORKSPACE_CREATION` | Stored instance policy; initially open | Pins workspace creation independently of signup. `closed`, `invite`, `invite_only`, `disabled`, `0` and `false` disable it (case-insensitive); other values enable it. Native environment and Worker bindings use the same setting. |
| `OPENWARP_EMAIL_WEBHOOK` | Unset | HTTP relay receiving `{to,subject,text}` for account mail |
| `OPENWARP_EMAIL_TOKEN` | Unset | Optional bearer authentication for the mail relay |

Password signups always require a verified email address: registration issues no session until the link is opened, and the first verified account claims instance ownership. Emails asserted by a configured identity provider (Google, GitHub, Apple, OpenAI, workspace OIDC, SAML, an accepted invite or SCIM) are treated as verified and do not trigger a second round-trip. Without a mail provider the server still starts: outside production it writes verification and reset links to its log, while a production server refuses new password signups and leaves SSO sign-in available. Set the public URL before sending account links. Forgot-password responses are intentionally generic and do not prove message delivery.

Without the override, the instance owner changes workspace creation in Settings or with `PUT /api/instance/workspaces` and `{"open":false}`. `GET /api/instance` reports `workspace_creation_open` and `workspace_creation_env_locked`; the public `GET /api/auth/providers` reports the effective creation policy. Closing creation suppresses personal workspaces for password and social registration, including the first account, but does not disable signup or invitation acceptance. Login never recreates a deleted workspace. The API refuses to close creation with no workspaces, or delete the last workspace while creation is closed. If an operator pins creation closed on an empty database, change the deployment setting to bootstrap a workspace.

## Social authentication

| Variable | Purpose |
| --- | --- |
| `OPENWARP_GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `OPENWARP_GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `OPENWARP_GOOGLE_ISSUER` | Override the default Google issuer for a compatible identity provider |
| `OPENWARP_GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `OPENWARP_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `OPENWARP_GITHUB_WEB` | Override GitHub's web endpoint, such as for Enterprise |
| `OPENWARP_GITHUB_API` | Override GitHub's API endpoint |
| `OPENWARP_APPLE_CLIENT_ID` | Sign in with Apple Services ID |
| `OPENWARP_APPLE_CLIENT_SECRET` | Apple client-secret JWT generated with your Sign in with Apple key; rotate it before its `exp` |
| `OPENWARP_APPLE_ISSUER` | Override the Apple issuer, such as for a test provider |
| `OPENWARP_OPENAI_CLIENT_ID` | OpenAI client ID (`oaiapp_...`) |
| `OPENWARP_OPENAI_CLIENT_SECRET` | OpenAI OAuth client secret |
| `OPENWARP_OPENAI_ISSUER` | Override the OpenAI issuer, such as for a test provider |
| `OPENWARP_MICROSOFT_CLIENT_ID` | Microsoft Entra ID application (client) ID |
| `OPENWARP_MICROSOFT_CLIENT_SECRET` | Entra client secret |
| `OPENWARP_MICROSOFT_TENANT` | Tenant ID, or `common`, `organizations` or `consumers`; defaults to `common` |
| `OPENWARP_MICROSOFT_ISSUER` | Override the Entra v2.0 issuer, such as for a sovereign cloud |
| `OPENWARP_OKTA_CLIENT_ID` | Okta client ID |
| `OPENWARP_OKTA_CLIENT_SECRET` | Okta client secret |
| `OPENWARP_OKTA_ISSUER` | Okta authorization-server issuer, such as `https://org.okta.com/oauth2/default` |
| `OPENWARP_AUTH0_CLIENT_ID` | Auth0 client ID |
| `OPENWARP_AUTH0_CLIENT_SECRET` | Auth0 client secret |
| `OPENWARP_AUTH0_ISSUER` | Auth0 tenant issuer, such as `https://tenant.auth0.com/` |
| `OPENWARP_GITLAB_CLIENT_ID` | GitLab OIDC client ID |
| `OPENWARP_GITLAB_CLIENT_SECRET` | GitLab OIDC client secret |
| `OPENWARP_GITLAB_ISSUER` | GitLab issuer; defaults to `https://gitlab.com` |
| `OPENWARP_SLACK_CLIENT_ID` | Slack Sign in with Slack client ID |
| `OPENWARP_SLACK_CLIENT_SECRET` | Slack client secret |
| `OPENWARP_SLACK_ISSUER` | Slack issuer; defaults to `https://slack.com` |
| `OPENWARP_SALESFORCE_CLIENT_ID` | Salesforce connected-app client ID |
| `OPENWARP_SALESFORCE_CLIENT_SECRET` | Salesforce client secret |
| `OPENWARP_SALESFORCE_ISSUER` | Salesforce issuer; defaults to `https://login.salesforce.com` (use `https://test.salesforce.com` or your My Domain for other orgs) |
| `OPENWARP_ATLASSIAN_CLIENT_ID` | Atlassian OAuth client ID |
| `OPENWARP_ATLASSIAN_CLIENT_SECRET` | Atlassian client secret |
| `OPENWARP_ATLASSIAN_ISSUER` | Atlassian issuer; defaults to `https://auth.atlassian.com` |
| `OPENWARP_X_CLIENT_ID` | X OAuth 2.0 client ID |
| `OPENWARP_X_CLIENT_SECRET` | X client secret; leave unset for a public client that uses PKCE only |
| `OPENWARP_X_WEB` | X authorization origin; defaults to `https://x.com` |
| `OPENWARP_X_API` | X API origin; defaults to `https://api.x.com` |
| `OPENWARP_OIDC_ISSUER` | Issuer URL of any other OIDC identity provider (Keycloak, Authentik, OneLogin, Ping, …) |
| `OPENWARP_OIDC_CLIENT_ID` | Client ID registered with that provider |
| `OPENWARP_OIDC_CLIENT_SECRET` | Client secret; leave unset for a public client that uses PKCE only |
| `OPENWARP_OIDC_NAME` | Button label, such as `Acme SSO`; defaults to `SSO` |
| `OPENWARP_OIDC_SCOPES` | Space-separated scopes; defaults to `openid email profile`, and `openid` is added if omitted |
| `OPENWARP_OIDC_AUTHORIZATION_ENDPOINT` | Override the discovered authorization endpoint |
| `OPENWARP_OIDC_TOKEN_ENDPOINT` | Override the discovered token endpoint |
| `OPENWARP_OIDC_JWKS_URI` | Override the discovered JWKS URI |
| `OPENWARP_OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` or `client_secret_post`; defaults to the method discovery advertises, preferring POST |

Each provider needs both its ID and secret, except the custom OIDC provider, which needs an issuer and client ID, and a public X client, which needs only a client ID. Unconfigured providers are not advertised. Callback paths are `/api/auth/social/<provider>/callback` for `google`, `github`, `apple`, `openai`, `microsoft`, `okta`, `auth0`, `gitlab`, `slack`, `salesforce`, `atlassian`, `x` and `oidc` at the public origin. Apple sends its authorization response as a form POST, so its callback accepts POST as well as GET, and its redirect URI must be HTTPS with a domain (no IP address or `localhost`). Providers that advertise S256, plus OpenAI, Microsoft, Okta, Auth0, GitLab, Salesforce, Atlassian, X and custom OIDC, use PKCE. Microsoft accepts the tenant-specific issuer from the token's `tid` claim and falls back to `preferred_username` or `upn` when the `email` claim is absent. X requires the `users.read users.email` scopes and reads the account's `confirmed_email`; it fails closed when X does not return one. The custom provider reads discovery metadata from `OPENWARP_OIDC_ISSUER`; the explicit endpoint variables let an IdP without usable metadata work. It verifies RS256/384/512, PS256/384/512 and ES256/384 `id_token` signatures against the provider JWKS, checks `iss`, `aud` (including `azp` when multiple audiences are present), `exp` and `nonce`, and binds each identity to the issuer plus subject. Workspace-specific OIDC settings are not these instance-level social variables.

## Proxy and egress policy

| Variable | Default | Behavior |
| --- | --- | --- |
| `OPENWARP_TRUST_PROXY` | Disabled | `1` enables forwarded client-IP handling from trusted peers |
| `OPENWARP_TRUSTED_PROXIES` | `127.0.0.1/32,::1` | Comma-separated proxy IPs or CIDRs |
| `OPENWARP_ALLOW_PRIVATE_EGRESS` | Disabled | `1` permits private/loopback destinations for the production checks applied to OIDC, audit webhooks, and log streams |
| `OPENWARP_ALLOWED_DB_HOSTS` | Empty | Comma-separated `host[:port]` allowlist for dynamic database leases (PostgreSQL, MySQL and MariaDB); empty disables that capability |

Proxy trust requires both enabling the flag and matching the connection peer. It does not make all client-supplied forwarding headers trustworthy.

Private egress is an intentional exception, not a general recommendation. Do not assume one setting constrains every provider-specific request. Apply network-layer egress policy and give integrations only the credentials they need.

## AI endpoints

| Variable | Default | Behavior |
| --- | --- | --- |
| `OPENWARP_AI_ENDPOINTS` | Empty | JSON array of exact allowed chat-completion URLs. Workspace administrators can select only these destinations, including explicitly trusted private endpoints |

AI is off per workspace until an administrator enables it. Provider keys are encrypted and write-only. Metadata disclosure, confirmed actions, and local value matching have separate switches. Native inference refuses redirects and ambient proxies; Workers inference is unavailable. BYOK does not imply local processing: the configured endpoint receives permitted context and the question. See [assistant and security insights](AI.md) for the disclosure policy and limits.

## Workspace settings

Workspace administrators manage these through `GET`/`PUT /api/orgs/{org_id}/settings` rather than process variables:

- IP allowlist and audit forwarding settings.
- OIDC issuer, client ID, encrypted client secret, and redirect URI.
- OIDC automatic provisioning and allowed-domain policy.

Changing an OIDC issuer without a replacement client secret clears the stored secret. Settings reads do not return the plaintext OIDC secret. Environment restriction and approval requirements have their own policy endpoint.

See [API](API.md) and [console](CONSOLE.md) for the related operations.

## CLI environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENWARP_HOST` | Saved host, project host, then local port 8080 | Instance origin |
| `OPENWARP_TOKEN` | Saved token | Explicit token for a command |
| `OPENWARP_CONFIG` | `~/.openwarp/config.json` | User configuration path |
| `OPENWARP_NO_KEYRING` | Unset | `1` disables OS credential storage |
| `OPENWARP_PRIVKEY` | Unset | Recovery kit for E2E operations |

The current-directory `.openwarp.json` supplies `app_id` and `env_id` defaults. The saved user host has precedence over the project host unless an explicit host option/environment value is set. Review [CLI host selection](CLI.md#host-and-token-selection) when using several instances.

## Compose-only variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_USER` | `openwarp` | Database user in the bundled stack |
| `POSTGRES_DB` | `openwarp` | Database name |
| `POSTGRES_PASSWORD` | Required | Database password interpolated into the server URL |

Choose a URL-safe password, or correctly encode URL-special characters when building your own connection string. Keep persistent database credentials consistent with the initialised volume; changing an environment variable is not itself a database password change.

## Backup helper variables

| Variable | Default |
| --- | --- |
| `DATABASE_URL` | `sqlite:///data/openwarp.db` |
| `BACKUP_DIR` | `/backups` |
| `RETENTION_DAYS` | `14` |

The backup helper's database default differs from the server's local default. Always supply it explicitly. See [backup and restore](BACKUP.md).

## Fixed implementation limits

| Limit | Current value |
| --- | --- |
| Request body | 8 MiB |
| HTTP handler timeout | 300 seconds |
| Provider request timeout | 30 seconds |
| Password session lifetime | 7 days |
| Machine token lifetime | 1 hour |
| Dynamic lease TTL | Default 1 hour, clamped between 60 seconds and 30 days |
| Custom environment name | 1-32 letters, digits, hyphens, or underscores |
| Standard secret key | 1-128 letters, digits, underscores, dots, or hyphens; uppercased |
| Standard secret path | Nonempty, at most 256 characters, no control characters |

These are implementation constraints, not paid tiers. Provider-specific limits also apply.

[Deployment](DEPLOY.md) · [Security](SECURITY.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Documentation index](README.md)
