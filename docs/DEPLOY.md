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
| `OPENWARP_ENV` | `production` refuses to start without an external master key |
| `OPENWARP_MASTER_KEY` | 32 bytes base64; wraps every environment data key |
| `OPENWARP_PUBLIC_URL` | Public origin used for OAuth issuers and redirects |
| `OPENWARP_SECURE_COOKIES` | `1` forces the `Secure` cookie flag |
| `OPENWARP_TRUST_PROXY` | `1` enables `X-Forwarded-For` from trusted proxies |
| `OPENWARP_TRUSTED_PROXIES` | Peer addresses allowed to send `X-Forwarded-For` |
| `OPENWARP_ALLOW_PRIVATE_EGRESS` | `1` allows OIDC issuers, log streams and audit webhooks on loopback/private addresses in production |
| `OPENWARP_SIGNUPS` | `open` or `closed`; when set it overrides the console toggle |
| `OPENWARP_GOOGLE_CLIENT_ID` / `OPENWARP_GOOGLE_CLIENT_SECRET` | Google sign-in |
| `OPENWARP_GOOGLE_ISSUER` | Override for a Google-compatible IdP |
| `OPENWARP_GITHUB_CLIENT_ID` / `OPENWARP_GITHUB_CLIENT_SECRET` | GitHub sign-in |
| `OPENWARP_GITHUB_WEB` / `OPENWARP_GITHUB_API` | GitHub Enterprise endpoints |
| `OPENWARP_APPLE_CLIENT_ID` / `OPENWARP_APPLE_CLIENT_SECRET` | Sign in with Apple; the secret is the ES256 client-secret JWT |
| `OPENWARP_APPLE_PRIVATE_KEY`, `_TEAM_ID`, `_KEY_ID` | Generate Apple's client secret from a `.p8` key instead of storing a JWT |
| `OPENWARP_OPENAI_CLIENT_ID` / `OPENWARP_OPENAI_CLIENT_SECRET` | Sign in with ChatGPT |
| `OPENWARP_MICROSOFT_CLIENT_ID` / `OPENWARP_MICROSOFT_CLIENT_SECRET` | Microsoft Entra ID |
| `OPENWARP_MICROSOFT_TENANT` | Tenant ID, or `common`, `organizations`, `consumers`; defaults to `common` |
| `OPENWARP_OKTA_ISSUER`, `OPENWARP_OKTA_CLIENT_ID`, `OPENWARP_OKTA_CLIENT_SECRET` | Okta |
| `OPENWARP_AUTH0_ISSUER`, `OPENWARP_AUTH0_CLIENT_ID`, `OPENWARP_AUTH0_CLIENT_SECRET` | Auth0 |
| `OPENWARP_GITLAB_CLIENT_ID` / `OPENWARP_GITLAB_CLIENT_SECRET` | GitLab OIDC; `OPENWARP_GITLAB_ISSUER` overrides the default |
| `OPENWARP_SLACK_CLIENT_ID` / `OPENWARP_SLACK_CLIENT_SECRET` | Slack |
| `OPENWARP_SALESFORCE_CLIENT_ID` / `OPENWARP_SALESFORCE_CLIENT_SECRET` | Salesforce; `OPENWARP_SALESFORCE_ISSUER` selects sandbox or My Domain |
| `OPENWARP_ATLASSIAN_CLIENT_ID` / `OPENWARP_ATLASSIAN_CLIENT_SECRET` | Atlassian |
| `OPENWARP_X_CLIENT_ID`, optional `OPENWARP_X_CLIENT_SECRET` | X OAuth 2.0 with PKCE |
| `OPENWARP_{PROVIDER}_TOKEN_AUTH_METHOD` | `client_secret_post`, `client_secret_basic`, `private_key_jwt` or `client_secret_jwt` |
| `OPENWARP_{PROVIDER}_PRIVATE_KEY`, `_KEY_ID`, `_PRIVATE_KEY_ALG` | `private_key_jwt` signing key (RS256 or ES256) |
| `OPENWARP_ALLOWED_DB_HOSTS` | `host[:port],...` allowed for dynamic Postgres leases; empty disables the feature |
| `OPENWARP_METRICS_TOKEN` | Enables `GET /metrics`; the token is required as a bearer |
| `OPENWARP_EMAIL_WEBHOOK` | HTTP relay that receives `{to,subject,text}` and forwards it to your mail provider |
| `OPENWARP_EMAIL_TOKEN` | Optional bearer sent to the email relay |
| `OPENWARP_REQUIRE_EMAIL_VERIFICATION` | `1` blocks password sign-in until the emailed link is opened; requires the webhook |
| `REDIS_URL` | Optional session cache |

Google redirect URI: `{OPENWARP_PUBLIC_URL}/api/auth/social/google/callback`.
GitHub callback URL: `{OPENWARP_PUBLIC_URL}/api/auth/social/github/callback`.
GitHub needs the `read:user` and `user:email` scopes; only a verified address
can create or match an account. Other callbacks follow
`{OPENWARP_PUBLIC_URL}/api/auth/social/<provider>/callback`. Apple posts its
authorization response, so its callback accepts POST as well as GET. An
`OPENWARP_APPLE_PRIVATE_KEY` avoids the six-month client-secret JWT rotation;
supply the `.p8` contents plus the team ID and key ID. X needs the `users.read`
and `users.email` scopes and a confirmed account email.

## Workspace OIDC group mapping

Workspace settings accept `oidc_groups_claim` (default `groups`) and
`oidc_group_roles`, a JSON object mapping group names to `owner`, `admin` or
`developer`. On each SSO login a matching group sets the member's role; the
highest-privileged match wins, no match leaves the current role, and the last
owner is never demoted.

Set `oidc_group_membership` to let a configured group grant membership even
without an invite. It is still limited by `oidc_allowed_domains` and instance
signups, and the mapped role is applied. Without the flag, group claims update
the role of existing members but never create membership.

## Identity linking

A signed-in user can attach a provider identity with
`/api/auth/social/<provider>/start?link=1` or
`/api/auth/oidc/<org>/start?link=1`. The callback binds the provider subject to
that account instead of creating or signing in another user. `GET
/api/me/identities` lists the bindings and `POST /api/me/identities/unlink`
removes one. An identity belongs to one account; linking never merges accounts
or changes the account email. The console exposes the same controls under
Settings.

When a provider or SSO login presents an email that already belongs to an
account, the browser is sent to a proof step instead of being rejected. The user
enters the account password, plus a TOTP or recovery code when MFA is enabled,
or requests an emailed confirmation link. Only after that proof is the identity
bound. A wrong password or code links nothing, challenges are single use, and
they expire after 10 minutes. The endpoints are `POST /api/auth/link/complete`,
`POST /api/auth/link/email` and `GET /api/auth/link/verify`.

## Back-channel logout

Register these endpoints with the IdP:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/<provider>/backchannel-logout
{OPENWARP_PUBLIC_URL}/api/auth/oidc/<org>/backchannel-logout
```

Each accepts a form-encoded `logout_token`, verifies its signature against the
provider JWKS, checks `iss`, `aud`, `exp`, the back-channel logout event and a
single-use `jti`, then revokes every session for the bound subject. Tokens that
carry only `sid` are rejected because no IdP session ID is stored; `sub` is
required. Bindings are recorded on each OIDC login, so an account that has not
signed in since this feature was deployed cannot be resolved until its next
login.

## Signups and invitations

Signups are open on a fresh instance. The instance owner can close them under
Settings, or set `OPENWARP_SIGNUPS=closed` to pin the policy. With signups
closed, an admin invites an address from Members: existing accounts are added
directly, new addresses get a single-use link valid for seven days. The invitee
sets a password from that link, or signs in with a configured social provider,
which redeems the invite and applies its role.

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
token and pending refresh pair for the account.

Password signups always require a verified email address. Registration issues no
session until the 24-hour link is opened, and the first verified account owns the
instance. A production server refuses new password signups when no email relay is
configured, while SSO sign-in remains available; outside production the links are
written to the server log. Social and SSO logins arrive with provider-verified
addresses.

## Operational checks

- `GET /health` is unauthenticated and checks the database; it returns 503
  when the database cannot be queried.
- `GET /metrics` is disabled unless `OPENWARP_METRICS_TOKEN` is set. Scrape with
  `Authorization: Bearer $OPENWARP_METRICS_TOKEN`.
- The server drains connections on `SIGTERM` and `SIGINT`.
- Backups: see [BACKUP.md](BACKUP.md).
