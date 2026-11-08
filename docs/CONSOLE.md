# Console guide

The browser console is served by OpenWarp at the instance root. It uses the same API and access rules as the CLI. A workspace in the console is an organisation (`org`) in API routes.

## Find your way around

| Area | Tasks |
| --- | --- |
| Apps | Create applications, select environments, manage secrets |
| Members & access | Invite members, manage roles and teams, review access and proposals, configure machine identities and tokens |
| Integrations | Manage sync destinations, dynamic leases, rotations, and sharing tools |
| Audit log | Inspect workspace activity |
| Settings | Workspace configuration, sign-in settings, MFA, and instance policy where permitted |

Available actions depend on your role and selected workspace. The first registered account is the instance owner; workspace ownership does not automatically confer that instance-level authority.

## Accounts and recovery

Register or sign in using a password. Google, Microsoft, Apple, GitHub, Okta, Auth0, GitLab, Atlassian, Slack, Salesforce, OpenAI and X appear when the instance operator has configured them. A password signup must open the emailed verification link before signing in; provider sign-in trusts the address the provider asserts. Invitations can admit new people even when public signup is closed.

Save the recovery kit shown during account creation. It is your private key, not an API token. If password reset asks for the kit, supplying it preserves the existing key. Choosing to discard a lost key prevents that account from decrypting existing E2E grants.

Enable TOTP MFA from settings and keep the recovery codes somewhere other than your authenticator device. If verification email or reset delivery fails, contact your instance operator; a generic success message does not prove the relay sent the email.

## Delete an account or workspace

Settings includes Delete account. Only a signed-in account session can use it, not a service key or OAuth token. Transfer or delete every workspace you own first, even if it has another owner. If issued API keys or live CLI/OAuth sessions remain, the console shows their counts and asks for confirmation before revoking credentials and deleting the account.

Members & access lists members, role controls, removal and Make owner. Ownership can move only to an active, verified member; the previous owner becomes an admin. The instance owner must separately use Transfer instance in Settings to hand control to another active, verified account. The last usable account may delete itself after deleting its workspaces.

A workspace owner can use Delete workspace in Settings after typing its exact name and confirming. This removes the workspace's stored applications, secrets, grants, identities, runners, certificates and configuration. It does not erase copies already delivered to clients or providers, or uninstall an SSH CA from hosts. The local deletion batch rolls back on database failure, including on Workers. Provider operations are separate from the local transaction. Revoke dynamic leases first; an unresolved lease prevents workspace deletion. Failed issuance can leave a pending reservation that requires operator reconciliation.

## Workspaces and applications

Select the workspace before changing membership or application data. Create an application from Apps and give it a descriptive name. Application readme content can record ownership, purpose, and operational notes; do not put plaintext credentials there.

New applications include Development, Staging, and Production environments. Custom environment names support letters, digits, hyphens, and underscores, up to 32 characters. Application and environment IDs are separate from these names. The CLI's discovery commands return IDs for automation.

## Standard secrets and drafts

1. Open an application and environment.
2. Add or edit a secret with its key, value, path, type, comment, and tags as needed.
3. Review the pending draft changes and selected environment.
4. Deploy changes to save them.

A draft is local UI state until deployed. Do not assume another browser or the CLI can read it. Review pending edits before changing context or leaving the page. Imports, restores, deletes, and other actions may execute immediately rather than joining the same draft batch; read the action's confirmation.

When you stage a `secret` value, the console asks the server whether the same value already exists elsewhere in the workspace. If it does, the warning names the application, environment, key and path, and each entry has a "Go to" action. "Use anyway" stages the value; "Back" returns to the form. The warning is advisory. It does not cover sealed or config values, E2E environments, or environments you cannot open. Workspace admins can turn the check off in Settings; app admins can turn it off under App settings. Both switches default to on.

| Type | Intended behavior |
| --- | --- |
| `secret` | A readable value for authorised users |
| `sealed` | A value that is not returned after saving; its type cannot be changed in place to reveal it |
| `config` | Configuration managed through the same secret workflow |

Keys are uppercased on standard secret writes. A path distinguishes identical names in different locations. Use conventional environment-variable names when values will reach a process or integration.

Reveal and copy actions expose plaintext on your device. Comments and tags help describe ownership or usage, but should not contain additional credentials.

## History, overrides, and references

Use a secret's history to inspect prior versions and restore an intended value. Restoring changes the current state; confirm the environment and version first. Sealed history does not provide a plaintext recovery channel.

A personal override changes your effective value without changing the shared base value. Integrations sync shared values rather than your personal overrides. Do not use an override as evidence that another user's application will receive the same configuration.

Standard environment reads can resolve references such as `${KEY}` and `${/path/KEY}`. Resolution is bounded rather than an arbitrary template language. Keep reference chains short and verify exported output before depending on them.

## Import, export, and comparison

Import accepts dotenv text. Review both the destination and any keys that already exist before applying it. Export produces plaintext, which needs the same protection as the original credentials.

Environment comparison and cloning are available through API operations. Do not assume that copying secrets copies every policy, integration, or access grant. Consult the [API reference](API.md) for the implementation surface when a task is not available in the console.

## Members and automation access

Invite people by email and choose the narrowest suitable role. Managed developers have write and automation permissions; they are not read-only users. For a read-only role, use a custom permission list and verify the resulting access.

Teams organise members. Environment policy can restrict access or require approval for non-admin writes. Review proposals and access requests in context: the requester, target environment, permissions, and lifetime matter.

Use app service tokens or machine identities for automation instead of a person's password. Record a newly issued credential securely, scope it, and revoke it when no longer needed. OAuth client scopes and workspace permissions both apply.

## Integrations and sharing

Select the source environment and destination before creating an integration. Sync sends shared, non-sealed SSE values to the provider. Test is implemented for Trigger.dev, Instabox, Boat, and Daytona; other kinds require a sync to exercise their connection, which can write remote data.

Only supported providers understand dry-run and mirror options. Mirror can delete previously managed remote names. Review the [integration guide](INTEGRATIONS.md) before using it.

Lockbox provides a one-time sharing flow. The complete link is sensitive, including its fragment. Share it only with the intended recipient and avoid preview services that might consume it.

## End-to-end environments

E2E environments show a dedicated decrypt panel rather than the ordinary SSE editing flow. Supply the recovery kit only in the trusted client. Browser decryption happens locally, but you still trust the JavaScript delivered by the instance.

Use the [CLI's E2E commands](CLI.md#end-to-end-environments) to create, write, read, and grant wrapped keys. Removing a grant prevents future access to that wrapped key through the server; it cannot erase plaintext or keys that a recipient already copied.

## Administrative settings

Workspace settings include IP allowlists and OIDC configuration. Test policy changes with a second authorised session before ending your working session. Only trust forwarded client IPs when the instance operator has configured the actual reverse proxies.

The PKI card creates two kinds of authority. An X.509 CA issues service certificates with a CRL. An SSH CA mints short-lived OpenSSH user certificates: create it once, copy the printed `TrustedUserCAKeys` block to every host that should accept those certificates, then grant each workspace role the principals it may request. Save grants as one role per line, `role: pattern, pattern`, with an optional trailing `(30m)` to cap that role's lifetime.

Manage an SSH CA to see the CA fingerprint, the sshd block, the issued certificates and a revoke action. A certificate can only name a principal its role is granted; a bare `*` means any local account including `root`, so only a workspace owner can save one. Certificates for `root` or under a bare `*` grant need a second factor, so the command line prompts for the emailed code rather than the console issuing one.

Register hosts here too: a host certificate is only issued for a hostname and public key pair an admin registered, because a host certificate is exactly as trustworthy as the key it names. Removing a registration is how a host key is rotated. Revoking records the certificate, but a host enforces it only after refreshing its `RevokedKeys` file, served here as both the plain list and an OpenSSH KRL.

Closing signups is an instance policy, while inviting members is a workspace action. A deployment-level `OPENWARP_SIGNUPS` setting can lock the console toggle.

[Getting started](GETTING_STARTED.md) · [Security model](SECURITY.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Documentation index](README.md)

## Device certificates without a TPM

The PKI card creates root and intermediate CAs, selects the active CA, lists the device inventory and mints one-time enrollment or renewal codes. It also shows expiring-certificate counts, imports and exports CSV, manages groups, and configures the enrollment hook and hardware attestation. Select the CA, add a device name and optional environment or group, then use **Enroll** to copy the single-use code and nonce to the device. **Renew** mints a code that revokes the previous certificate when the replacement enrolls. The CA certificate shown below the table is the trust anchor for the MQTT broker. **Revoke** retires the device's active certificate. The console never displays a device private key, because enrollment only accepts a CSR.

Select device checkboxes, or use Select all, then Mint selected codes to provision
up to 500 existing devices. The result lists successful codes and per-device
errors. Download codes CSV includes each device id, code, nonce and expiry;
protect this file as a credential and remove it after provisioning. Switching
workspace or CA clears selected devices and downloadable code results. Expiry
summaries are also emailed through the configured mailer to verified, active
workspace owners and admins.
