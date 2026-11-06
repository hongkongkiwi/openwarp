# Deployment

The repository includes a Compose stack with OpenWarp, PostgreSQL 17, and Redis 7. You can also run the native server against SQLite or PostgreSQL. Start with [getting started](GETTING_STARTED.md) for local evaluation; this guide covers a deployed instance.

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
- An existing local database adopts its `meta.master` into `meta.kms_root` on
  the first boot with a KMS and deletes the plaintext row.
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

Workspace OIDC is configured separately in workspace settings through `oidc_issuer`, `oidc_client_id`, `oidc_client_secret`, and `oidc_redirect_uri`. Set provisioning and allowed-domain policy deliberately. Changing the issuer without supplying a replacement secret clears the old secret. SCIM provisioning requires workspace context and administrative credentials; see the [API reference](API.md).

## Run the native server

Build the server:

```bash
cargo build --release -p openwarp-server
```

Run it under your service manager with an existing data directory and securely provisioned environment:

```bash
OPENWARP_ENV=production \
DATABASE_URL=sqlite:///var/lib/openwarp/openwarp.db \
ADDR=127.0.0.1:8080 \
  ./target/release/openwarp-server
```

This assumes `OPENWARP_MASTER_KEY` is already set securely. For PostgreSQL or MySQL/MariaDB, set `DATABASE_URL` to your database connection string instead (`mysql://` or `mariadb://`). Redis is optional through `REDIS_URL`. Run as an unprivileged account with only the filesystem and network access it needs.

OpenWarp is a native service. Cloudflare Workers cannot run this binary as-is; the storage and networking layers would need a separate port.

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

The Workers build must use `--no-default-features`: the LDAP feature, ring,
SAML, SMTP and the native Postgres/Redis clients are excluded there. Runtime
configuration is read from Worker variables and secrets; the full key list is
`crates/server/src/envcfg.rs`. `OPENWARP_EMAIL_WEBHOOK` (an HTTP relay) is the
email provider on Workers; password signup is otherwise unavailable in
production.

What works on Workers: registration with emailed verification, password and
GitHub sign-in, OIDC login (pure-Rust JWT verification), TOTP, SCIM, tokens,
E2E and SSE secrets, approvals, log streams, audit webhooks, integrations,
PKI CA and certificate issuance, dynamic PostgreSQL, MySQL and MariaDB leases,
and the rotation and delivery maintenance cron.

The MySQL lease client is built into the Worker because no MySQL library
compiles for wasm; it speaks the protocol directly over the socket and uses TLS
when the lease URL sets `require_ssl=true`. MySQL is a lease target only on
Workers: the deployment's own storage stays in the Durable Object, and a
`DATABASE_URL` of `mysql://` is native-only.

Answers 501 with a clear error on Workers: LDAP sign-in, SAML, SSH file sync,
SMTP (use the HTTP relay), OCI Vault (RSA request signing), and the WebSocket
`/api/live` stream. `/api/live` exists only natively; poll the audit endpoint
instead. OCSP/CRL endpoints and master-key rotation are also native-only.

Operational limits: every request serialises through the single Durable
Object; `OPENWARP_TRUST_PROXY` is inert (the runtime address is the client);
`X-Forwarded-For` is ignored; session cookies are always `Secure` and the
OAuth issuer defaults to `https://`. Metrics counters are per isolate and reset
on a cold start. Durable Object SQLite point-in-time recovery covers 30 days
and is not available under `wrangler dev`; see [BACKUP.md](BACKUP.md).

## Platform limits

OpenWarp is a native service. A Cloudflare Workers or other WASM port, which is
not part of this repository, cannot open raw TCP/TLS sockets and cannot offer
LDAP. The `ldap` cargo feature carries the directory client, its routes and its
console entry: building with `--no-default-features` produces a binary with no
LDAP code at all, `/api/auth/providers` reports `ldap: false`, and the console
hides the directory card and sign-in button. The rest of the server still needs
its database driver and OS networking, so that build is not a Workers
deployment by itself. Directories that publish OIDC (Entra ID, Keycloak,
Authentik, Dex) remain reachable through the OIDC flow on any target.

On a native deployment the directory is usually on a private network. Add its
CA to the host trust store, or paste the CA PEM into the directory settings.
`OPENWARP_ENV=production` treats loopback and private targets as blocked
egress; set `OPENWARP_ALLOW_PRIVATE_EGRESS=1` to allow the internal directory,
exactly as for a self-hosted OIDC issuer.

[Configuration](CONFIGURATION.md) · [Backup and restore](BACKUP.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Documentation index](README.md)
