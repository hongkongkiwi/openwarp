# Deploying OpenWarp

Docker compose is the supported path. `docker compose up --build` starts the
server, Postgres 17 and Redis 7. The compose file refuses to start until
`OPENWARP_MASTER_KEY` and `POSTGRES_PASSWORD` are set.

```bash
# 32 random bytes, base64
export OPENWARP_MASTER_KEY="$(head -c 32 /dev/urandom | base64)"
export POSTGRES_PASSWORD="$(head -c 24 /dev/urandom | base64)"
docker compose up -d --build
```

## Before going live

1. Terminate TLS in front of the server and set `OPENWARP_PUBLIC_URL` to the
   public HTTPS origin. It fixes the OAuth issuer and marks the session cookie
   `Secure`; without it the issuer is derived from the `Host` header.
2. If you run behind a reverse proxy, set `OPENWARP_TRUST_PROXY=1` and list the
   proxy addresses in `OPENWARP_TRUSTED_PROXIES` (comma-separated IPs or CIDRs).
   `X-Forwarded-For` is only honoured when the peer connection comes from one of
   those addresses, so an exposed port cannot spoof the client IP.
3. Register the first account immediately. The first account is the instance
   owner and is the only one that can change the signup policy.
4. Create the recovery kit backup for every user. It is shown once.

## Environment

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | `sqlite://file.db` or `postgres://...` |
| `ADDR` | Listen address, default `0.0.0.0:8080` |
| `OPENWARP_ENV` | `production` refuses to start without an external root key or KMS |
| `OPENWARP_MASTER_KEY` | 32 bytes base64; local root key. Optional when `OPENWARP_KMS_URL` is set |
| `OPENWARP_KMS_URL` | KMS bridge base URL; enables external root and environment-key wrapping |
| `OPENWARP_KMS_TOKEN` | Optional bearer token sent to the KMS bridge |
| `OPENWARP_KMS_KEY_ID` | Key identifier recorded with each wrapped value; default `primary` |
| `OPENWARP_PUBLIC_URL` | Public origin used for OAuth issuers and redirects |
| `OPENWARP_SECURE_COOKIES` | `1` forces the `Secure` cookie flag |
| `OPENWARP_TRUST_PROXY` | `1` enables `X-Forwarded-For` from trusted proxies |
| `OPENWARP_TRUSTED_PROXIES` | Peer addresses allowed to send `X-Forwarded-For` |
| `OPENWARP_SIGNUPS` | `open` or `closed`; when set it overrides the console toggle |
| `OPENWARP_AUTH_PROVIDERS` | Comma list of `password`, `google`, `github`, `oidc`; pins sign-in methods and overrides the console |
| `OPENWARP_GOOGLE_CLIENT_ID` / `OPENWARP_GOOGLE_CLIENT_SECRET` | Google sign-in |
| `OPENWARP_GOOGLE_ISSUER` | Override for a Google-compatible IdP |
| `OPENWARP_GITHUB_CLIENT_ID` / `OPENWARP_GITHUB_CLIENT_SECRET` | GitHub sign-in |
| `OPENWARP_GITHUB_WEB` / `OPENWARP_GITHUB_API` | GitHub Enterprise endpoints |
| `OPENWARP_ALLOWED_DB_HOSTS` | `host[:port],...` allowed for dynamic Postgres leases; empty disables the feature |
| `OPENWARP_METRICS_TOKEN` | Enables `GET /metrics`; the token is required as a bearer |
| `OPENWARP_EMAIL_WEBHOOK` | HTTP relay that receives `{to,subject,text}` and forwards it to your mail provider; also enables emailed second factors |
| `OPENWARP_EMAIL_TOKEN` | Optional bearer sent to the email relay |
| `OPENWARP_REQUIRE_EMAIL_VERIFICATION` | `1` blocks password sign-in until the emailed link is opened; requires the webhook |
| `OPENWARP_RP_ID` | WebAuthn relying-party ID; defaults to the host in `OPENWARP_PUBLIC_URL` |
| `OPENWARP_RP_ORIGIN` | WebAuthn origin; defaults to `OPENWARP_PUBLIC_URL` |
| `REDIS_URL` | Optional session cache |

Google redirect URI: `{OPENWARP_PUBLIC_URL}/api/auth/social/google/callback`.
GitHub callback URL: `{OPENWARP_PUBLIC_URL}/api/auth/social/github/callback`.
GitHub needs the `read:user` and `user:email` scopes; only a verified address
can create or match an account.

## Key management and encryption modes

Set `OPENWARP_KMS_URL` to keep the root key and every managed environment key
outside the database. The bridge protocol is in the [security model](SECURITY.md).
A fresh database stores only a KMS-wrapped root; an existing database that
already has a local master adopts it on first boot, stores the same root as
`kms_root` and deletes the plaintext `meta.master` row. The KMS then becomes the
only root, so back up its key. After changing `OPENWARP_KMS_KEY_ID`, call
`POST /api/instance/rewrap` as the instance owner to wrap every environment key
under the new key ID. Old key IDs must remain unwrappable by the KMS adapter
until that finishes.

After upgrading, call `POST /api/instance/encrypt-metadata` once as the
instance owner. It encrypts existing secret paths and tags and replaces the old
SHA-256 lookup hashes with HMAC blind indexes. New writes do this automatically.

Without a KMS, `OPENWARP_MASTER_KEY` is still required in production and the
database is only as private as the host. Use managed (`sse`) environments for
dynamic leases, PKI and any feature that needs server-side plaintext.

## Delegated environments and the runner

A delegated environment moves the environment key to the client and the
customer-run sync runner. The server stores ciphertext, seals integration
configuration to the runner, and queues sync jobs instead of calling providers.

Create a runner from the console or the CLI:

```bash
openwarp runner create --org ORG_ID --name vpc-runner
```

Store the printed `runner_key` with the runner and keep the `runner_token`
there too. Create the environment with the CLI, passing the same runner's ID
and public key:

```bash
openwarp e2e create --app APP_ID --name production --delegated \
  --runner-id RUNNER_ID --runner-pubkey RUNNER_PUBLIC_KEY
```

Run the runner in the customer network:

```bash
OPENWARP_URL=https://secrets.example.com \
OPENWARP_RUNNER_TOKEN=... \
OPENWARP_RUNNER_KEY=... \
openwarp-runner
```

The runner polls `/api/runner/jobs`, unwraps the environment key with its own
private key, decrypts the integration config and secrets in memory, pushes to
the provider, and reports the result. The server never holds the plaintext or
the provider credentials. A claimed job is reclaimable after ten minutes if the
runner crashes.

Removing a member from an `e2e` or delegated environment sets a rekey flag. Run
`openwarp e2e revoke --env ENV_ID --email ADDRESS` to remove the grant and
rotate in one command, or `openwarp e2e rekey --env ENV_ID` if the grant was
already removed. The revoke command sends the removal and the new grants in one
rekey request, so the grant is never absent while the old ciphertext is still
readable. Rotation rewraps the new key to the remaining grantees and the runner.

## Signups and invitations

Signups are open on a fresh instance. The instance owner can close them under
Settings, or set `OPENWARP_SIGNUPS=closed` to pin the policy. With signups
closed, an admin invites an address from Members: existing accounts are added
directly, new addresses get a single-use link valid for seven days. The invitee
sets a password from that link, or signs in with a configured social provider,
which redeems the invite and applies its role. The console now derives the
account keys in the browser, so the invite password never reaches the server.

## Client-derived authentication

New accounts, invites, password resets and the OAuth consent page use the
protocol in [AUTH-PROTOCOL.md](AUTH-PROTOCOL.md). The browser derives an
authentication key and a separate wrapping key with PBKDF2-HMAC-SHA256
(600,000 iterations), sends only the authentication key and an AES-GCM-wrapped
private key, and proves login with a single-use HMAC challenge. The server never
receives the password or the wrapping key, so an operator with full server
access cannot decrypt end-to-end data for these accounts.

Version 1 password accounts keep working. A password reset upgrades them to the
client-derived protocol; an explicit upgrade would require the recovery kit in
the browser and is not exposed as a separate action yet. The server still holds
the authentication key, so it can authenticate as a user, and it still serves
the client JavaScript. See the security model for what that does and does not
cover.

## Sign-in methods and two-factor authentication

The instance owner can turn password, Google, GitHub or OIDC sign-in off under
Settings, but at least one method must stay on. `OPENWARP_AUTH_PROVIDERS` pins
the list for an operator, for example `github` or `password,google`. A listed
method whose credentials are missing stops the server at startup. Disabling
password also blocks password registration, reset and the OAuth consent
password form, so confirm another method works before turning it off.

Users add TOTP, passkeys and emailed codes from Settings. Email codes and email
verification share `OPENWARP_EMAIL_WEBHOOK`; without it the email-code option
is reported unavailable. Passkeys require a secure browser context (HTTPS or
localhost). `OPENWARP_RP_ID` and `OPENWARP_RP_ORIGIN` override the relying-party
values derived from `OPENWARP_PUBLIC_URL` when a proxy or split origin needs
it. Registration and authentication challenges are kept server-side and expire
after five minutes.

## Password reset and email verification

Password reset needs an email relay: `OPENWARP_EMAIL_WEBHOOK` receives a JSON
body with `to`, `subject` and `text`, and the link inside it points back at
`OPENWARP_PUBLIC_URL`. `POST /api/auth/forgot` always answers the same way, so
it cannot be used to discover accounts.

A reset link does not decrypt anything on its own. The user supplies their
recovery kit and a new password, which re-wraps the same private key and keeps
end-to-end environments readable. A user who has lost the kit can pass
`discard_e2e_key: true`, which generates a new key pair and makes existing
end-to-end environments unreadable. Either path revokes every session, OAuth
token and pending refresh pair for the account. If the account has a second
factor, the reset response is an MFA challenge; no session is issued until it
is completed.

Email verification is opt-in with `OPENWARP_REQUIRE_EMAIL_VERIFICATION=1`. New
password registrations then start unverified, receive a 24-hour link, and cannot
sign in until it is opened. Social and SSO logins arrive with verified
addresses. The server refuses to start if verification is required but no email
relay is configured, because nobody could complete it.

## Operational checks

- `GET /health` is unauthenticated and checks the database; it returns 503
  when the database cannot be queried.
- `GET /metrics` is disabled unless `OPENWARP_METRICS_TOKEN` is set. Scrape with
  `Authorization: Bearer $OPENWARP_METRICS_TOKEN`.
- The server drains connections on `SIGTERM` and `SIGINT`.
- Backups: see [BACKUP.md](BACKUP.md).
