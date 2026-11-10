# Deployment

The repository includes a Compose stack with OpenWarp, PostgreSQL 17, Redis 7 and a Caddy edge. The native server supports SQLite, PostgreSQL and MySQL/MariaDB. A separate Cloudflare Workers target uses SQLite-backed Durable Object storage. Start with [getting started](GETTING_STARTED.md) for local evaluation; this guide covers a deployed instance.

## Deployment checklist

- An external, backed-up master key and persistent database storage.
- HTTPS at a reverse proxy and the correct public URL.
- A private bootstrap window for the first account.
- Explicit signup, proxy-trust, and outbound-network policies.
- A mail relay if password reset or email verification is needed.
- A tested backup and restore procedure.

Read the [security model](SECURITY.md) before storing production secrets. The PostgreSQL driver currently uses `NoTls`; browser HTTPS does not encrypt database connections. Keep database traffic on an isolated network or provide an encrypted transport separately.

## Compose setup

From the repository root, generate credentials for a new instance:

```bash
export OPENWARP_MASTER_KEY="$(openssl rand -base64 32)"
export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
```

Save these values securely before continuing. Do not regenerate the master key when restarting an existing instance. The password uses hexadecimal characters so it can be inserted into the Compose database URL without URL-escaping issues.

[`docker-compose.yml`](../docker-compose.yml) requires both variables and sets `OPENWARP_ENV=production`. It publishes port 8080 through a Caddy edge and persists PostgreSQL in the `pgdata` volume. Redis is included in this stack, but the native server does not require it.

### More than one server

Every `server` container uses the same Postgres database and the same `OPENWARP_MASTER_KEY`. That pair is the whole join secret: a process that starts with both is a replica, and stopping it removes it. There is no membership list to edit.

```bash
docker compose up -d --scale server=3
```

The edge container is the only published port. It re-resolves the `server` name, checks `/health`, and drops a replica that stops answering. WebSocket connections to `/api/live` stay on the replica that accepted them and receive events written by any replica. Do not point a second server at the SQLite file; only Postgres is shared across processes.

### Pass deployment settings into the container

A variable exported in your host shell or present in Compose's `.env` file is not automatically part of the server container's environment. Add each server setting to the Compose service, or use an override such as `compose.override.yaml`:

```yaml
services:
  server:
    environment:
      OPENWARP_PUBLIC_URL: ${OPENWARP_PUBLIC_URL:?set the public HTTPS origin}
      OPENWARP_SECURE_COOKIES: "1"
      OPENWARP_SIGNUPS: ${OPENWARP_SIGNUPS:-closed}
      OPENWARP_TRUST_PROXY: ${OPENWARP_TRUST_PROXY:-0}
      OPENWARP_TRUSTED_PROXIES: ${OPENWARP_TRUSTED_PROXIES:-127.0.0.1/32,::1}
```

Set the public URL to your actual HTTPS origin. Explicitly select signup policy for the private bootstrap described below; do not accidentally prevent creation of the initial account. Add mail, social login, and metrics variables the same way if you use them. See the [configuration reference](CONFIGURATION.md).

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 server
```

## Schema migrations

Migrations are numbered and recorded in `schema_migrations`. The server applies
them at boot, or a deploy job can run them without starting the listener or
needing the master key:

```bash
DATABASE_URL=... openwarp-server --migrate   # prints the current version and exits
```

Existing databases created before the ledger are baselined at version 1 and
upgraded in place. Take a backup first; see [BACKUP.md](BACKUP.md).

## Encryption and key custody

- SSE environments use a per-environment key wrapped by the instance root. Set
  `OPENWARP_KMS_URL`, `OPENWARP_KMS_TOKEN` and `OPENWARP_KMS_KEY_ID` to wrap the
  root and environment keys through an external KMS/HSM bridge. After changing
  key IDs, run `POST /api/instance/rewrap` as the instance owner. Back up the KMS
  key; the database alone is not enough.
- The native server can auto-unseal in production with the KMS bridge alone;
  `OPENWARP_MASTER_KEY` is not required in that configuration. KMS errors stop
  startup rather than generating another root. Workers require the master-key
  binding and do not use this native bridge.
- An existing local database adopts its `meta.master` into `meta.kms_root` on
  the first boot with a KMS and deletes the plaintext row. If a master-key
  variable is also set, it takes precedence and this adoption does not run.
- Run `POST /api/instance/encrypt-metadata` once as the instance owner after
  upgrading a database written before secret metadata was encrypted.
- Delegated and E2E environments keep the environment key on the client. See
  [ENCRYPTION.md](ENCRYPTION.md).

## Sign-in methods and second factors

- `OPENWARP_AUTH_PROVIDERS` pins the enabled methods as a comma-separated list.
  Without it the instance owner can change them under instance settings. At
  least one configured method must stay enabled.
- Passkeys need `OPENWARP_RP_ID` and `OPENWARP_RP_ORIGIN` (the HTTPS origin).
  Both must match what browsers see.
- Email second factors use the configured mail provider; outside production a
  suppressed code is written to the server log.
- Client-derived sign-in is documented in [AUTH-PROTOCOL.md](AUTH-PROTOCOL.md).
  The console still uses password registration and sign-in.

## Delegated environments and the runner

Create a runner in the workspace, then start `openwarp-runner` in the customer
network with `OPENWARP_URL`, `OPENWARP_RUNNER_TOKEN` and `OPENWARP_RUNNER_KEY`
(the base64 X25519 private key). It polls outbound only; `OPENWARP_RUNNER_ONCE=1`
runs one pass and `OPENWARP_RUNNER_INTERVAL` sets the poll interval. Provider
configs are sealed to the runner, and sealed secrets are never sent.

## Operational checks

Treat rendered Compose configuration and logs as sensitive: they can include credentials or connection strings. The source Compose file binds port 8080 on host interfaces. Restrict it with firewall or binding configuration before exposing the host. If a reverse proxy runs in another container, its address is not necessarily loopback.

## HTTPS and reverse proxies

Terminate TLS at your reverse proxy and forward requests to OpenWarp. Set `OPENWARP_PUBLIC_URL` to the externally reachable HTTPS origin so OAuth metadata, redirects, and account links use the correct address.

For client-IP policies behind a proxy:

1. Set `OPENWARP_TRUST_PROXY=1`.
2. Set `OPENWARP_TRUSTED_PROXIES` to the actual proxy peer IPs or CIDRs.
3. Have the proxy replace untrusted inbound forwarding headers.
4. Verify the direct application port is not an unintended public entry point.

The server honours `X-Forwarded-For` only when the connection peer is trusted. Do not use broad trusted ranges merely to make an allowlist pass.

## Bootstrap and signup policy

Keep the service private while bootstrapping. Allow registration, create the first account, and save its recovery kit. The first account is the instance owner, which is distinct from being an owner of an individual workspace.

Then close signups in instance Settings or pin `OPENWARP_SIGNUPS=closed` in the deployment. When that variable is set, it overrides the console policy. If using the override example above, temporarily choose `OPENWARP_SIGNUPS=open` for the private bootstrap, then change it and recreate the server container.

Workspace administrators can invite people. Existing accounts can be added directly; new addresses receive a single-use invitation link with a seven-day lifetime. Follow the invite flow rather than reopening public registration for each person.

## Email delivery

`OPENWARP_EMAIL_WEBHOOK` points to a relay that accepts an HTTP JSON body:

```json
{
  "to": "recipient@example.invalid",
  "subject": "Account message",
  "text": "Plain-text message containing the account link"
}
```

The relay is responsible for sending the email through your provider. `OPENWARP_EMAIL_TOKEN` optionally adds bearer authentication to the relay request. Protect relay access and logs because message bodies contain sensitive account links.

Password reset requires the relay. The forgot-password endpoint returns a generic response, so a successful response does not prove that a message was delivered. Test actual delivery and link origins before opening registration.

Password signups always require email verification. Registration issues no session until the link is opened, and the first verified account claims instance ownership. Verification links last 24 hours. Configure the relay before opening password registration: without one the server still starts, but a production server refuses new password signups while SSO sign-in remains available; outside production it writes verification and reset links to its log. Emails asserted by a configured provider are treated as verified. Password reset with the recovery kit preserves the user's private key; deliberately replacing a lost key loses access to old E2E grants. See [security](SECURITY.md).

## Social login and workspace SSO

Google login needs `OPENWARP_GOOGLE_CLIENT_ID` and `OPENWARP_GOOGLE_CLIENT_SECRET`. Register this callback with the provider:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/google/callback
```

GitHub login needs `OPENWARP_GITHUB_CLIENT_ID` and `OPENWARP_GITHUB_CLIENT_SECRET`, with callback:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/github/callback
```

Apple login needs `OPENWARP_APPLE_CLIENT_ID` (the Services ID) and `OPENWARP_APPLE_CLIENT_SECRET` (the ES256 client-secret JWT generated with your Sign in with Apple key; Apple limits its lifetime to six months, so rotate it before it expires). Register this callback:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/apple/callback
```

Apple requires an HTTPS redirect URI with a domain, and it posts the authorization response, so the server accepts both GET and POST on that path. Apple returns a private relay address when the user hides their email; treat it as a verified address for that Apple subject.

OpenAI login needs `OPENWARP_OPENAI_CLIENT_ID` (`oaiapp_...`) and `OPENWARP_OPENAI_CLIENT_SECRET` from the Sign in with ChatGPT client registration, with callback:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/openai/callback
```

OpenAI sign-in uses the authorization code flow with PKCE (S256). GitHub login requests `read:user` and `user:email`. Provider buttons appear only when configured. Provider login requires verified email information and does not silently attach an identity to an existing password account based only on email.

Microsoft Entra ID, Okta, Auth0, GitLab, Slack, Salesforce and Atlassian use OIDC with the same callback pattern:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/<provider>/callback
```

Microsoft needs `OPENWARP_MICROSOFT_CLIENT_ID` and `OPENWARP_MICROSOFT_CLIENT_SECRET`; `OPENWARP_MICROSOFT_TENANT` defaults to `common`, and a single-tenant deployment can set its tenant ID. Entra work accounts often omit the `email` claim, so the server falls back to `preferred_username` or `upn`.

Okta and Auth0 also need their issuer: `OPENWARP_OKTA_ISSUER` and `OPENWARP_AUTH0_ISSUER`. GitLab, Slack, Salesforce and Atlassian default to their public issuers; override `OPENWARP_GITLAB_ISSUER`, `OPENWARP_SLACK_ISSUER`, `OPENWARP_SALESFORCE_ISSUER` or `OPENWARP_ATLASSIAN_ISSUER` for self-managed, sandbox or My Domain deployments.

X uses OAuth 2.0 with PKCE rather than OIDC:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/x/callback
```

Set `OPENWARP_X_CLIENT_ID` and, for a confidential client, `OPENWARP_X_CLIENT_SECRET`. The X app must request `users.read` and `users.email`, and the account needs a confirmed email; sign-in fails rather than inventing one when X returns no address.

Discord, LinkedIn and WorkOS each need their `OPENWARP_<PROVIDER>_CLIENT_ID` and `OPENWARP_<PROVIDER>_CLIENT_SECRET`, with `DISCORD`, `LINKEDIN` or `WORKOS` substituted for `<PROVIDER>`. Register the matching callback:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/discord/callback
{OPENWARP_PUBLIC_URL}/api/auth/social/linkedin/callback
{OPENWARP_PUBLIC_URL}/api/auth/social/workos/callback
```

Discord uses OAuth with `identify email`; `OPENWARP_DISCORD_API` overrides its API base. LinkedIn uses OIDC; `OPENWARP_LINKEDIN_ISSUER` overrides its default issuer. WorkOS uses its User Management authorization and authentication endpoints; `OPENWARP_WORKOS_API` overrides its API base. `OPENWARP_WORKOS_PROVIDER` selects the provider (default `authkit`); `OPENWARP_WORKOS_CONNECTION_ID`, when set, takes precedence over that selection. Discord and WorkOS require a verified email in the provider response. API and issuer overrides pass the same URL and egress checks as other identity providers: use HTTPS, or HTTP on loopback for local testing. In production, the egress check rejects localhost and private or local IP literals unless the operator sets `OPENWARP_ALLOW_PRIVATE_EGRESS=1`; outside production, that check permits private destinations. Hostnames are not checked against their resolved addresses, so use network egress controls to restrict them. A refused URL or destination prevents sign-in rather than falling back to another endpoint.

Workspace OIDC is configured separately in workspace settings through `oidc_issuer`, `oidc_client_id`, `oidc_client_secret`, and `oidc_redirect_uri`. Set provisioning and allowed-domain policy deliberately. Changing the issuer without supplying a replacement secret clears the old secret. SCIM provisioning requires workspace context and administrative credentials; see the [API reference](API.md).

## Run the native server

Build the server:

```bash
cargo build --release -p openwarp-server
```

That command produces a core-only binary. SAML, SCIM, X.509 PKI, SSH
certificates, transit, workload identity, change requests and LDAP are Cargo
features that the default set omits, so add them to the build and then grant
them per workspace before they answer:

```bash
cargo build --release -p openwarp-server --features enterprise,redis-cache
```

See [enterprise surfaces](FEATURES.md#enterprise-surfaces-build-features-and-workspace-grants)
for the individual feature names, the grant API and the container build argument.
Enabling a feature and forgetting the grant is the usual cause of a 403 that
names the surface.

Run it under your service manager with an existing data directory and securely provisioned environment:

```bash
OPENWARP_ENV=production \
DATABASE_URL=sqlite:///var/lib/openwarp/openwarp.db \
ADDR=127.0.0.1:8080 \
  ./target/release/openwarp-server
```

This assumes `OPENWARP_MASTER_KEY` is already set securely. For PostgreSQL or MySQL/MariaDB, set `DATABASE_URL` to your database connection string instead (`mysql://` or `mariadb://`). Redis is optional through `REDIS_URL`. Run as an unprivileged account with only the filesystem and network access it needs.

The native executable runs directly or in Docker. Cloudflare Workers uses a separate WebAssembly artifact from the same application library; see [Cloudflare Workers](#cloudflare-workers).

Cloudflare as a proxy in front of the native server is supported. Orange-cloud the hostname, set `OPENWARP_TRUST_PROXY=1`, and set `OPENWARP_TRUSTED_PROXIES` to the addresses your origin actually sees, which are Cloudflare's egress ranges rather than the visitor's address. The server reads `X-Forwarded-For` only from a peer in that list, so an IP allowlist still sees the visitor. WebSockets pass through Cloudflare, and `/api/live` sends a ping every 30 seconds so the edge's idle timeout does not close a quiet console. A dropped socket reconnects with `?since=<id>`. This does not make the server run on Workers.

## Health, metrics, and limits

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/health
```

`/health` checks database connectivity and returns 503 when it cannot query the database. It does not prove mail delivery, provider sync, or recovery readiness.

`/metrics` is disabled unless `OPENWARP_METRICS_TOKEN` is set. Use bearer authentication to scrape it and keep the endpoint restricted. The server caps request bodies at 8 MiB and applies a five-minute handler timeout. Provider requests have their own timeouts. The server drains connections on SIGTERM or SIGINT.

## Upgrades and rollback

1. Record the deployed source revision and configuration.
2. Back up the database and preserve the matching master key.
3. Rehearse the new version against an isolated restore, with outbound automation blocked.
4. Deploy during a controlled maintenance window and check health, login, secret access, and any integrations you depend on.
5. If rollback is necessary, use a compatible database snapshot as well as the old binary. Do not assume startup schema changes are reversible.

Do not remove the PostgreSQL volume during an upgrade. Keep old backups until the new version has passed a restore rehearsal.

## Cloudflare Workers

The Workers target runs the same Rust application inside one SQLite-backed
Durable Object: the object's synchronous SQLite handle sits behind the async
`Db` API, so handlers, authorization and the console are shared rather than
reimplemented. Requests are forwarded to that object by `crates/server/src/worker.rs`.

Configure and deploy:

```bash
cargo install worker-build --version 0.8.7
cargo install wasm-bindgen-cli --version 0.2.130
npx wrangler secret put OPENWARP_MASTER_KEY    # 32 random bytes, base64
(cd crates/server && worker-build --release --no-default-features)
npx wrangler deploy
```

The Workers build must use `--no-default-features`: LDAP, ring, SMTP and the
native database drivers are excluded there. `jsonwebtoken` uses its
`rust_crypto` backend for OIDC verification; PKI issuance uses `x509-cert` and
`p256`. Neither path requires ring on Workers. Dynamic PostgreSQL leases use
the Workers socket transport rather than the native connection pool.

Runtime configuration comes from Worker variables and secrets; the key list is
`crates/server/src/envcfg.rs`. Set `OPENWARP_PUBLIC_URL` to the public HTTPS
origin before enabling sign-in. The shared application uses it for callback
URLs and Secure session cookies. Configure an HTTP email provider, such as
`OPENWARP_EMAIL_WEBHOOK`; production password signup requires email delivery.

What works on Workers: registration with emailed verification, password and
GitHub sign-in, OIDC login (pure-Rust JWT verification), TOTP, email second
factors, recovery codes, SCIM, tokens, E2E and SSE secrets, approvals, log streams,
audit webhooks, HTTP integrations, PKI CA and certificate issuance, dynamic
PostgreSQL, MySQL and MariaDB leases, and the rotation and delivery maintenance cron.

The MySQL lease client is built into the Worker because no MySQL library
compiles for wasm; it speaks the protocol directly over the socket and uses TLS
when the lease URL sets `require_ssl=true`. MySQL is a lease target only on
Workers: the deployment's own storage stays in the Durable Object, and a
`DATABASE_URL` of `mysql://` is native-only.

SAML and passkeys share the native verification libraries. The vendored clock
patches select the Workers clock without replacing signature verification.
OCSP and CRL generation use portable timestamps and Rust signing libraries.
Use `scripts/worker-protocol-smoke.mjs` to exercise passkey assertions and
independently verify OCSP and CRL signatures with OpenSSL. Run
`scripts/worker-saml-smoke.sh` for signed SAML login, invalid-signature rejection
and replay rejection against workerd. `scripts/worker-key-smoke.mjs` checks KMS
outage recovery, rotation failure safety and restart key validation. OCI Vault uses the shared Rust RSA
signer.

The `/api/live` WebSocket transport uses hibernating Durable Object sockets.
Admission and each delivered event check the current credential, workspace,
environment, scope and IP policy. Reconnect with `since` to replay retained
events. Attachments retain a credential hash and cursor, not a bearer token.
Environment-scoped tokens cannot open the workspace-wide stream.

LDAP routes are compiled out. SSH file sync, SMTP and integrations that need
client TLS certificates return errors rather than running native implementations.

The KMS bridge uses asynchronous HTTP on both deployments. A configured bridge
must unwrap the existing root successfully before requests are served. Master
rotation validates encrypted records and commits their replacements together;
update the external master-key setting before restarting. A stale setting fails
the persisted key check. Rotation is disabled on shared PostgreSQL and MySQL/MariaDB because
replicas do not yet reload a changed master key.

All requests go through one Durable Object. This gives one storage location,
not a separate application replica in every region. The Worker supplies
`CF-Connecting-IP` as the client address; leave forwarded-proxy trust disabled.
Metrics counters are per isolate and reset on a cold start. Durable Object
recovery is separate from a native database backup; see [BACKUP.md](BACKUP.md).

## Platform limits

The native and Workers targets share application code, but differ in storage, networking and protocol support. Use the [Workers support list](#cloudflare-workers) when deciding whether that target fits your deployment. Disabling default Cargo features alone does not turn a native binary into a Worker; the Worker build and runtime bindings are also required.

The `ldap` Cargo feature carries the directory client, routes and console entry. Builds without it report `ldap: false` from `/api/auth/providers` and hide the directory settings and sign-in button. Directories that publish OIDC can instead use the OIDC flow, subject to the configured issuer and egress policy.

The current Workers artifact excludes LDAP. The `ldap` Cargo feature carries
Keycloak, Authentik and Dex, can use the shared OIDC flow instead.

Workers supports outbound sockets, which the PostgreSQL lease adapter uses.
That does not make the native LDAP, SMTP or SSH subprocess implementations
portable. Those features need their own Workers transport or must run in the
native deployment.

On a native deployment the directory is usually on a private network. Add its
CA to the host trust store, or paste the CA PEM into the directory settings.
`OPENWARP_ENV=production` treats loopback and private targets as blocked
egress; set `OPENWARP_ALLOW_PRIVATE_EGRESS=1` to allow the internal directory,
exactly as for a self-hosted OIDC issuer.

[Configuration](CONFIGURATION.md) · [Backup and restore](BACKUP.md) · [Development](DEVELOPMENT.md) · [Documentation index](README.md)
