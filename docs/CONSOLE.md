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

Closing signups is an instance policy, while inviting members is a workspace action. A deployment-level `OPENWARP_SIGNUPS` setting can lock the console toggle.

The PKI card creates root and intermediate CAs, selects the active CA, lists the device inventory and mints one-time enrollment or renewal codes. It also shows expiring-certificate counts, imports and exports CSV, manages groups, and configures the enrollment hook and hardware attestation. Select the CA, add a device name and optional environment or group, then use **Enroll** to copy the single-use code and nonce to the device. **Renew** mints a code that revokes the previous certificate when the replacement enrolls. The CA certificate shown below the table is the trust anchor for the MQTT broker. **Revoke** retires the device's active certificate. The console never displays a device private key, because enrollment only accepts a CSR.

Select device checkboxes, or use Select all, then Mint selected codes to provision
up to 500 existing devices. The result lists successful codes and per-device
errors. Download codes CSV includes each device id, code, nonce and expiry;
protect this file as a credential and remove it after provisioning. Switching
workspace or CA clears selected devices and downloadable code results. Expiry
summaries are also emailed through the configured mailer to verified, active
workspace owners and admins.

[Getting started](GETTING_STARTED.md) · [Security model](SECURITY.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Documentation index](README.md)
