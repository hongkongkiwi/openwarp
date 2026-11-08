# Console guide

The browser console is served by OpenWarp at the instance root. It uses the same API and access rules as the CLI. A workspace in the console is an organisation (`org`) in API routes.

## Find your way around

| Area | Tasks |
| --- | --- |
| Apps | Create applications, select environments, manage secrets |
| Members & access | Invite members, manage roles and teams, review access and proposals, configure machine identities and tokens |
| Integrations | Manage sync destinations, dynamic leases, rotations, and sharing tools |
| Audit log | Inspect workspace activity, sync outcomes, and log-stream delivery attempts |
| Settings | Workspace configuration, sign-in settings, MFA, and instance policy where permitted |

Available actions depend on your role and selected workspace. The first registered account is the instance owner; workspace ownership does not automatically confer that instance-level authority. An unknown hash route renders a Not found screen with links back to Apps and Members & access instead of leaving a blank view.

## Appearance and languages

The console ships a light and a dark theme. With nothing chosen it follows the system colour scheme and re-resolves when the system changes; a toggle in the top bar (and on the sign-in card) cycles system, light and dark, and the Settings page has an Appearance & language card with explicit picks. The theme preference and explicit language overrides are stored in the browser (`localStorage`), so they apply per device and before signing in; the sign-in screen, console and one-time lockbox page all honour the choice.

The interface is translated into English, Traditional Chinese, Simplified Chinese, Japanese, Korean, Spanish, French, German and Brazilian Portuguese. The language defaults to the browser's own languages and can be overridden from the sign-in card, the top bar or Settings. Select System / browser to remove the override and detect the browser language again. Three limits are deliberate: text that comes from the server (error messages, audit details, provider hints with JSON examples) stays in English; a string a language has not yet translated falls back to English rather than vanishing; and values that come from your data (secret keys, app and environment names) are never rewritten even when they happen to match a UI label.

## Accounts and recovery

Register or sign in using a password. Google, Microsoft, Apple, GitHub, Okta, Auth0, GitLab, Atlassian, Slack, Salesforce, OpenAI and X appear when the instance operator has configured them. A password signup must open the emailed verification link before signing in; provider sign-in trusts the address the provider asserts. Invitations can admit new people even when public signup is closed.

Save the recovery kit shown during account creation. It is your private key, not an API token. If password reset asks for the kit, supplying it preserves the existing key. Choosing to discard a lost key prevents that account from decrypting existing E2E grants.

Enable TOTP MFA from settings and keep the recovery codes somewhere other than your authenticator device. If verification email or reset delivery fails, contact your instance operator; a generic success message does not prove the relay sent the email.

Settings also manages passkeys and browser sessions. Adding a passkey asks for your password first and then creates the WebAuthn credential in the browser; the recovery codes shown afterwards are the only fallback if the authenticator is lost. Removing a passkey requires the password again. The sessions card lists each signed-in browser session with its sign-in time and marks the current one; revoking another session ends it immediately, and revoking the current session signs this browser out. End all sessions revokes every browser session for the account, including the one you are using; API keys and OAuth tokens are unaffected. My tokens opens the API token list instead of browser sessions.

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

Compare and Clone sit in the environment toolbar. Compare lists keys only in this environment, only in the other one, and keys whose base values differ; it shows key names, never values, and needs read access to both. Clone copies readable base secrets into another server-encrypted environment of the same app, skips sealed values, and optionally overwrites keys that already exist. Neither action copies personal overrides, policies, integrations, grants, rotation schedules or history, and client-encrypted environments require the CLI instead. Consult the [OpenAPI contract](../openapi.json) when a task has no console control.

## Members and automation access

Invite people by email and choose the narrowest suitable role. Managed developers have write and automation permissions; they are not read-only users. For a read-only role, use a custom permission list and verify the resulting access.

Teams organise members. Environment policy can restrict access or require approval for non-admin writes. Review proposals and access requests in context: the requester, target environment, permissions, and lifetime matter.

Use app service tokens or machine identities for automation instead of a person's password. Record a newly issued credential securely, scope it, and revoke it when no longer needed. OAuth client scopes and workspace permissions both apply.

Members & access also contains three workspace tools:

- Batched change requests group managed-environment writes and deletions. Enter the environments and operations as JSON, then have a different admin review and approve the revision before applying it. An edit clears approval. See [batched change requests](CHANGE-REQUESTS.md).
- Workload trust configures an existing machine identity with an explicit environment, issuer, audience, subject, public JWKS and optional bound claims. Revoking trust invalidates its issued tokens. See [workload identity](WORKLOAD-IDENTITY.md).
- Transit encryption creates and rotates workspace keys and runs encrypt, decrypt or rewrap operations. Input plaintext is base64. The server processes plaintext, and rewrap permission is separate from decrypt permission. See [transit encryption](TRANSIT.md).

Review screens and transit decrypt responses display plaintext in the browser. Use these controls only on a trusted device; do not paste real credentials into recordings or shared screens.

## Managing apps, environments and teams

App settings (from an app's environment toolbar) edits the app name and its plain-text readme, toggles its reuse warning, or deletes the app. The readme is stored and shown as text, not rendered; do not put credentials in it. The delete action requires confirmation and removes the app's environments, secrets and grants; revoke dynamic leases first.

Env settings rename the environment, set how many versions history keeps (`0` keeps every version), restrict access to explicit grants, require an approved proposal for non-admin writes, or delete the environment. Policy changes apply immediately.

Teams group members for environment grants. Manage a team from Members & access to add or remove workspace members; roles are unchanged by team membership.

The audit log has three tabs. Audit shows workspace activity with a client-side filter over the loaded events and a Load older events control. Sync activity narrows the same events to integration, runner and rotation work. Delivery attempts lists log-stream deliveries with their stream, event, status and attempt count; failed rows name the stream so you can fix or remove it. Large workspaces should also use log streams for durable forwarding.

## Integrations and sharing

Select the source environment and destination before creating an integration. Sync sends shared, non-sealed SSE values to the provider. Test is implemented for Trigger.dev, Instabox, Boat, and Daytona; other kinds require a sync to exercise their connection, which can write remote data.

Each integration row can Edit it, open its sync History, run a sync, or delete it. Edit renames the integration, changes its kind, and replaces its stored configuration; the encrypted configuration is never shown back, so leave the field empty to keep the existing one. Configuration fields validate JSON as you type, name the exact error, and offer Format JSON. History lists the last 50 sync and sync-failure audit entries for that integration.

Only supported providers understand dry-run and mirror options. Mirror can delete previously managed remote names. Review the [integration guide](INTEGRATIONS.md) before using it.

Lockbox provides a one-time sharing flow. The complete link is sensitive, including its fragment. Share it only with the intended recipient and avoid preview services that might consume it.

## End-to-end environments

E2E environments show a dedicated decrypt panel rather than the ordinary SSE editing flow. Supply the recovery kit only in the trusted client. Browser decryption happens locally, but you still trust the JavaScript delivered by the instance.

Use the [CLI's E2E commands](CLI.md#end-to-end-environments) to create, write, read, and grant wrapped keys. Removing a grant prevents future access to that wrapped key through the server; it cannot erase plaintext or keys that a recipient already copied.

## Emergency lockdown

Workspace owners can halt a whole workspace from Settings, or choose **Project lockdown** on an app card to halt that project. A project is an application in the API. Confirm the selected scope before activation.

The web console permits read-only inspection of authorised metadata while the affected scope is halted. Secret values, exports, history and E2E keys remain unavailable, including to owners. All SDK, CLI, service-token, OAuth, machine and runner requests targeting the halted scope are rejected for reads as well as writes. Existing integration settings are preserved, but syncs cannot run or be added or resumed.

Only the actual workspace `owner` role can activate or restore either scope. These controls require the console's cookie-backed account session. Admins, custom roles and automation credentials cannot operate them. Workspace and project locks survive a restart and apply together: restoring a workspace leaves any separate project lockdown active, and restoring a project cannot bypass a workspace lockdown.

Non-owner members lose their existing sessions and OAuth credentials. Sessions are account-wide, so even a project halt signs those workspace members out of other projects. They can sign in again for read-only console inspection or use an unaffected scope. Restoration never restores revoked credentials or turns on integrations that were already paused.

The console clears cached secret values and drafts when it detects a halt. Open tabs check periodically, so they may take a few seconds to update.

Lockdown cannot erase values already copied by a client, secrets already sent to a provider, or a runner payload already downloaded. Previously created Lockbox shares have no workspace association and remain usable. Rotate exposed credentials and revoke external access separately when responding to an incident.

## Plan and enterprise features

Settings shows the current plan. A self-hosted installation has every core feature and needs no key. The SAML, workspace OIDC, LDAP and log-stream cards show an Enterprise label and stay unavailable until an enterprise license is installed by the instance operator; the rest of the console is unchanged. See [editions and licensing](EDITIONS.md).

## Administrative settings

Workspace settings include IP allowlists and OIDC configuration. Test policy changes with a second authorised session before ending your working session. Only trust forwarded client IPs when the instance operator has configured the actual reverse proxies.

The PKI card creates two kinds of authority. An X.509 CA issues service certificates with a CRL. An SSH CA mints short-lived OpenSSH user certificates: create it once, copy the printed `TrustedUserCAKeys` block to every host that should accept those certificates, then grant each workspace role the principals it may request. Save grants as one role per line, `role: pattern, pattern`, with an optional trailing `(30m)` to cap that role's lifetime.

Manage an SSH CA to see the CA fingerprint, the sshd block, the issued certificates and a revoke action. A certificate can only name a principal its role is granted; a bare `*` means any local account including `root`, so only a workspace owner can save one. Certificates for `root` or under a bare `*` grant need a second factor, so the command line prompts for the emailed code rather than the console issuing one.

Register hosts here too: a host certificate is only issued for a hostname and public key pair an admin registered, because a host certificate is exactly as trustworthy as the key it names. Removing a registration is how a host key is rotated. Revoking records the certificate, but a host enforces it only after refreshing its `RevokedKeys` file, served here as both the plain list and an OpenSSH KRL.

Closing signups is an instance policy, while inviting members is a workspace action. A deployment-level `OPENWARP_SIGNUPS` setting can lock the console toggle.

[Getting started](GETTING_STARTED.md) · [Security model](SECURITY.md) · [Development](DEVELOPMENT.md) · [Documentation index](README.md)
