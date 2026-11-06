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
| `OPENWARP_MICROSOFT_CLIENT_ID` / `OPENWARP_MICROSOFT_CLIENT_SECRET` | Microsoft Entra ID sign-in |
| `OPENWARP_MICROSOFT_TENANT` | Entra tenant, default `common`; pin it in production |
| `OPENWARP_APPLE_CLIENT_ID` / `OPENWARP_APPLE_TEAM_ID` / `OPENWARP_APPLE_KEY_ID` / `OPENWARP_APPLE_PRIVATE_KEY` | Apple sign-in; the private key is the `.p8` PEM |
| `OPENWARP_GITLAB_CLIENT_ID` / `OPENWARP_GITLAB_CLIENT_SECRET` | GitLab sign-in |
| `OPENWARP_X_CLIENT_ID` / `OPENWARP_X_CLIENT_SECRET` | X sign-in; the app needs `users.email` |
| `OPENWARP_DISCORD_CLIENT_ID` / `OPENWARP_DISCORD_CLIENT_SECRET` | Discord sign-in |
| `OPENWARP_LINKEDIN_CLIENT_ID` / `OPENWARP_LINKEDIN_CLIENT_SECRET` | LinkedIn sign-in |
| `OPENWARP_SLACK_CLIENT_ID` / `OPENWARP_SLACK_CLIENT_SECRET` | Slack sign-in |
| `OPENWARP_WORKOS_CLIENT_ID` / `OPENWARP_WORKOS_CLIENT_SECRET` | WorkOS AuthKit sign-in |
| `OPENWARP_ALLOWED_DB_HOSTS` | `host[:port],...` allowed for dynamic Postgres leases; empty disables the feature |
| `OPENWARP_METRICS_TOKEN` | Enables `GET /metrics`; the token is required as a bearer |
| `OPENWARP_EMAIL_WEBHOOK` | HTTP relay that receives `{to,subject,text}` and forwards it to your mail provider |
| `OPENWARP_EMAIL_TOKEN` | Optional bearer sent to the email relay |
| `OPENWARP_REQUIRE_EMAIL_VERIFICATION` | `1` blocks password sign-in until the emailed link is opened; requires the webhook |
| `REDIS_URL` | Optional session cache |

Every provider callback is
`{OPENWARP_PUBLIC_URL}/api/auth/social/{provider}/callback`, where provider is
one of `google`, `github`, `microsoft`, `apple`, `gitlab`, `x`, `discord`,
`linkedin`, `slack` or `workos`. GitHub needs the `read:user` and `user:email`
scopes; only a verified address can create or match an account. See
[docs/AUTH_PROVIDERS.md](AUTH_PROVIDERS.md) for the remaining scopes and
provider-specific setup.

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
