# Sign-in providers

Password sign-in is always available. OpenWarp also supports ten optional
OAuth 2.0 / OpenID Connect providers. A provider appears on the login page only
when its credentials are configured; an unconfigured provider returns 404.

Every provider uses the same callback pattern:

```text
{OPENWARP_PUBLIC_URL}/api/auth/social/{provider}/callback
```

Register that exact URL in the provider's developer console.

## Configuration

| Provider | Required variables | Optional variables |
| --- | --- | --- |
| `google` | `OPENWARP_GOOGLE_CLIENT_ID`, `OPENWARP_GOOGLE_CLIENT_SECRET` | `OPENWARP_GOOGLE_ISSUER` |
| `github` | `OPENWARP_GITHUB_CLIENT_ID`, `OPENWARP_GITHUB_CLIENT_SECRET` | `OPENWARP_GITHUB_WEB`, `OPENWARP_GITHUB_API` |
| `microsoft` | `OPENWARP_MICROSOFT_CLIENT_ID`, `OPENWARP_MICROSOFT_CLIENT_SECRET` | `OPENWARP_MICROSOFT_TENANT`, `OPENWARP_MICROSOFT_ISSUER` |
| `apple` | `OPENWARP_APPLE_CLIENT_ID`, `OPENWARP_APPLE_TEAM_ID`, `OPENWARP_APPLE_KEY_ID`, `OPENWARP_APPLE_PRIVATE_KEY` | `OPENWARP_APPLE_ISSUER` |
| `gitlab` | `OPENWARP_GITLAB_CLIENT_ID`, `OPENWARP_GITLAB_CLIENT_SECRET` | `OPENWARP_GITLAB_ISSUER` |
| `x` | `OPENWARP_X_CLIENT_ID`, `OPENWARP_X_CLIENT_SECRET` | `OPENWARP_X_WEB`, `OPENWARP_X_API` |
| `discord` | `OPENWARP_DISCORD_CLIENT_ID`, `OPENWARP_DISCORD_CLIENT_SECRET` | `OPENWARP_DISCORD_API` |
| `linkedin` | `OPENWARP_LINKEDIN_CLIENT_ID`, `OPENWARP_LINKEDIN_CLIENT_SECRET` | `OPENWARP_LINKEDIN_ISSUER` |
| `slack` | `OPENWARP_SLACK_CLIENT_ID`, `OPENWARP_SLACK_CLIENT_SECRET` | `OPENWARP_SLACK_ISSUER` |
| `workos` | `OPENWARP_WORKOS_CLIENT_ID`, `OPENWARP_WORKOS_CLIENT_SECRET` | `OPENWARP_WORKOS_API`, `OPENWARP_WORKOS_PROVIDER`, `OPENWARP_WORKOS_CONNECTION_ID` |

`GET /api/auth/providers` returns a boolean per provider plus a `providers`
array of `{id, label}` entries for the enabled ones.

## Provider notes

### Google

Uses OIDC discovery. The `email_verified` claim must not be `false`.
`OPENWARP_GOOGLE_ISSUER` exists for tests and Google-compatible IdPs.

### GitHub

Uses the OAuth 2.0 authorization-code flow and the `/user` plus `/user/emails`
APIs. The app needs `read:user` and `user:email`; only a verified address can
create an account. `OPENWARP_GITHUB_WEB` and `OPENWARP_GITHUB_API` point at
GitHub Enterprise.

### Microsoft

Uses Microsoft Entra ID v2.0 OIDC. `OPENWARP_MICROSOFT_TENANT` defaults to
`common`; set it to your tenant ID in production. The `email` claim must be
present: `preferred_username` is a directory identifier, not a verified email,
so it is not accepted. If your tenant omits `email` from id_tokens, add it as an
optional claim or use organisation OIDC. Tokens issued through `common` can come
from any Entra tenant, and a work account's `email` is controlled by that
tenant; pinning the tenant limits which directory can assert an address.

### Apple

Apple requires a client secret signed with the `.p8` key, not a static secret.
Set `OPENWARP_APPLE_TEAM_ID`, `OPENWARP_APPLE_KEY_ID` and
`OPENWARP_APPLE_PRIVATE_KEY` (the PKCS#8 PEM contents; literal `\n` escapes are
accepted). Apple returns the email only on first consent, so returning users are
matched by the stable subject. The callback accepts both `GET` and the
`form_post` request Apple sends.

### GitLab

Uses GitLab OIDC. `OPENWARP_GITLAB_ISSUER` selects a self-managed instance.

### X

Uses OAuth 2.0 with PKCE (`S256`). The X app needs the `users.email` permission;
the address is read from `confirmed_email`. Without that permission a returning,
already-linked user can still sign in, but a new account is refused because no
email is returned.

### Discord

Uses `identify email`. An account whose Discord email is not verified is
refused.

### LinkedIn

Uses LinkedIn's OpenID Connect provider with `openid profile email`.

### Slack

Uses Slack OIDC plus its `userinfo` endpoint, because Slack's id_token carries
only the subject. The email and `email_verified` values come from userinfo.

### WorkOS

Uses WorkOS User Management, not OIDC discovery. The authorize request defaults
to `provider=authkit`, which shows the AuthKit hosted UI and its configured
connections. Set `OPENWARP_WORKOS_PROVIDER` to another provider value, or set
`OPENWARP_WORKOS_CONNECTION_ID` to send users directly to one connection.
Register the callback URL as a redirect in the WorkOS dashboard.
`OPENWARP_WORKOS_API` overrides the API origin for tests.

## Not available as instance providers

- OpenAI/ChatGPT does not publish a static OAuth or OIDC client that a
  third-party app can use for general sign-in. Its "Sign in with ChatGPT" flow
  uses dynamic per-user client registration to share ChatGPT plan tokens, so it
  is not treated as an identity provider here.
- Okta, Auth0, Keycloak and other identity providers are supported through the
  per-organisation OIDC settings (`oidc_issuer`, `oidc_client_id`,
  `oidc_client_secret`, `oidc_redirect_uri`). That flow binds users to the
  organisation rather than to the instance.

## Account rules

- An identity binds to `(provider, subject)`, so changing the email at the
  provider does not move the account.
- A new account needs an email address. A provider that reports
  `email_verified=false` is refused.
- If an existing password account uses the same email, social sign-in returns a
  conflict instead of linking silently. Sign in with the password.
- Signup policy still applies. With signups closed, only an invited address is
  admitted.
- Login state is single-use and expires after ten minutes. X uses PKCE; OIDC
  providers receive a nonce, and it is checked when the provider returns one.
