# Editions and licensing

OpenWarp has two plans. A self-hosted installation needs no key and keeps every core feature. OpenWarp Enterprise adds a small set of directory, federation and audit-export features through an offline signed license.

## Self-hosted (default)

With no license configured, the instance runs on the self-hosted plan. There is no seat count, trial timer, usage report or network call. Core features include:

- secrets, sealed and config values, folders, tags, comments, history and restore
- end-to-end and delegated environments, the CLI, SDKs and every secret API
- password, social and instance-wide OIDC sign-in
- members, roles, custom roles, teams, invitations and IP allowlists
- change requests, approvals and access requests
- point-in-time recovery, rotation, dynamic leases, workload identity and transit
- workspace and project lockdown, audit logging with the hash chain and verification
- browser session management, lockbox, import, export and backup

OpenWarp does not paywall a security control. Lockdown, audit integrity, approvals, recovery and data access stay available without a license.

## Enterprise

Enterprise is the same installation plus a license. It unlocks:

| Feature | What it adds |
| --- | --- |
| Workspace SAML SSO | Per-workspace SAML identity provider, signed metadata, auto-provisioning and domain limits |
| Workspace OIDC SSO | Per-workspace OIDC issuer and client, allowed domains and auto-provisioning |
| LDAP directory | LDAPS search-then-bind sign-in with group to role mapping |
| SCIM 2.0 | User and group provisioning into members and teams |
| Audit log streaming | Log streams with HMAC-signed retries, the workspace audit webhook and delivery attempts |

Everything outside this table is core. The external KMS bridge stays in the self-hosted plan for now; HSM/KMIP enrollment, nested sub-organizations and private-network gateways are not gated because they are not implemented.

## Installing a license

Set the signed token in `OPENWARP_LICENSE` or point `OPENWARP_LICENSE_FILE` at a file that contains it. The whole file is read, so a trailing newline is fine.

```bash
OPENWARP_LICENSE_FILE=/etc/openwarp/license.jwt openwarp-server
```

The license is read at startup. Restart the server after changing it. The console shows the current plan in Settings; the instance owner also sees the licensed customer and expiry. `GET /api/instance/edition` returns the same status, with the commercial fields omitted for other members. No license data is sent anywhere.

Verification is offline: the server checks an ES256 signature against the embedded vendor public key (`kid` `ow-2026-01`), the issuer, the subject, the version and the expiry. There is no activation server and no phone-home.

## Expiry and invalid keys

- An expired, tampered or malformed key does not stop the server. It falls back to self-hosted, records a warning that Settings displays and logs the reason.
- Enterprise configuration is never deleted. Existing SAML, OIDC, LDAP and SCIM records and log streams remain in the database and become editable again when a valid key is installed.
- While self-hosted, enterprise routes return `403` with `code: "enterprise_feature"` and the feature key. SAML, workspace OIDC, LDAP and SCIM sign-in stop, new log streams cannot be created, and audit forwarding pauses. The audit log, its hash chain, its verification and stored delivery history stay readable.
- Core routes never consult the license.

Plan for expiry in advance: sign-in for users who rely on directory federation stops when the key lapses.

## Development builds

A debug build accepts `OPENWARP_LICENSE=development` outside `OPENWARP_ENV=production`. Release binaries and production configuration ignore that value and stay on self-hosted. `OPENWARP_LICENSE=none` forces self-hosted in any build.

The development value exists so tests and local development can exercise enterprise routes without a private key. It is not a production bypass.

## Issuing a license

The vendor private key never belongs in this repository. The current key is kept at `~/.openwarp/enterprise-signing-key.pem` with mode `0600`; back it up offline. Generate a token with:

```bash
node scripts/license-sign.mjs --customer "Acme Ltd" --days 365
```

The token goes to stdout and the summary to stderr. Rotate the signing key by replacing `ENTERPRISE_PUBLIC_KEY_PEM` and `KID` in `crates/server/src/edition.rs` together, then reissue every active license.

Licensing here is a compliance control, not DRM. The server is self-hosted and the source is inspectable, so a determined operator can patch the check. The signature makes accidental or casual use of enterprise features detectable and keeps the plans honest.
