# Core concepts

[Documentation index](README.md) · [Getting started](GETTING_STARTED.md)

OpenWarp separates where secrets belong, who may use them, and who holds the keys. This guide explains those distinctions before you configure access or automation.

## From instance to secret

```text
Instance
└── Workspace (org in the API)
    ├── Members, teams, roles and audit history
    └── Application
        ├── Development environment
        ├── Staging environment
        └── Production environment
            └── Secret at a path, with a key and value
```

| Term | Meaning |
| --- | --- |
| Instance | A deployed OpenWarp service and its persistent state |
| Workspace / organisation | A membership and administration boundary; API routes use `orgs` |
| Application | A project inside a workspace |
| Environment | A set of secrets and associated access, encryption and integration settings |
| Path | A folder-like namespace inside an environment, such as `/` or `/backend` |
| Secret key | The name of a value within its environment and path |
| Instance owner | An account with instance administration responsibilities |
| Workspace owner | A workspace role; instance ownership and workspace membership are different concepts |

Accounts can belong to multiple workspaces. An environment's ID is not its display name. Commands that request `ENV_ID`, `APP_ID` or `ORG_ID` expect the identifier returned by your instance.

A standard secret is identified by environment, path and normalised key. Two paths can contain the same key. Check a consumer's path handling before exporting both into a flat environment-variable map.

## Values, drafts and history

The console stages edits before you select **Deploy changes**. A draft is not a saved API value. Direct CLI and API writes have their own persistence behavior; they do not wait for the console's deployment action.

| Kind | How to think about it |
| --- | --- |
| `secret` | A value that authorised consumers can read |
| `sealed` | A write-only value that normal reads do not return; excluded from provider sync |
| `config` | Configuration data, with behavior documented in the feature reference |
| `ssh_key` | SSH key material used by the corresponding SSH integrations |

Personal overrides customise values for a user. Provider sync uses shared values rather than personal overrides. Secret references such as `${KEY}` and `${/path/KEY}` resolve other values; they are distinct from the CLI's explicit `ow://` reference consumption. See [CLI reference](CLI.md) and [feature reference](FEATURES.md).

Version history helps inspect and restore secret changes. It is not a database backup. Retention and permanent deletion can remove versions; a restore also does not undo copies already sent to a provider or consumer.

## Identity is only the first access check

A successful login identifies the caller. Access can still be narrowed by:

- Workspace membership and role permissions.
- Application or environment grants and restricted-environment policy.
- OAuth or service-token scopes and environment scope.
- Approval requirements and network policy.
- Workspace or project emergency lockdown.

A token with a broad scope does not create missing membership. A valid identity does not bypass an environment restriction. An administrative OAuth scope is separate from secret-read permission.

Use human login for interactive work. Use scoped service tokens, machine identities or [workload identity](WORKLOAD-IDENTITY.md) for automation. Avoid sharing a person's session with a CI job.

## Encryption changes where automation runs

| Mode | Environment key custody | Automation consequence |
| --- | --- | --- |
| `sse` | Server-managed | The server can decrypt for API reads and sync |
| `delegated` | Authorised clients and a customer-run runner | A runner decrypts queued sync jobs |
| `e2e` | Authorised clients | Clients decrypt; ordinary server-side sync is unavailable |

External KMS wrapping changes how server-managed keys are protected, but a server authorised to unwrap them can still decrypt. E2E claims require client-generated creation; the compatibility path that creates a key on the server has a different boundary.

The browser receives its code from the instance. An operator who changes that code can change what the browser does with keys. Read [encryption and key custody](ENCRYPTION.md) for the full threat model.

## Sync, rotation and dynamic credentials

These operations solve different problems:

| Operation | Purpose | What to verify |
| --- | --- | --- |
| Provider sync | Copy selected shared secrets to a destination | Per-provider results, naming rules and mirror deletions |
| Rotation | Change a managed secret, optionally through a provider adapter | New credential validity, local persistence and downstream delivery |
| Dynamic lease | Issue a temporary credential with an expiry | Target permissions, lease state and remote revocation |
| Transit encryption | Encrypt application data with workspace-managed keys | Key version, operation permissions and ciphertext storage |

A successful local write does not prove a provider accepted an update. Expiry and local revocation records are not substitutes for checking that the remote credential was removed when an operation fails.

See [integrations](INTEGRATIONS.md), [feature reference](FEATURES.md) and [Transit](TRANSIT.md).

## Recovery requires more than a password

Keep the database backup, matching instance master key, user recovery kits and deployment credentials in appropriate separate stores. A recovery kit contains private key material; it is not a database snapshot. Changing `OPENWARP_MASTER_KEY` to a new random value does not rotate an existing database's keys.

Removing a member cannot erase secrets or keys already downloaded. Rotate affected credentials and environment keys where necessary. Emergency lockdown pauses access within its documented scope, but does not recall remote copies.

Read [backup and restore](BACKUP.md) before storing data you cannot afford to lose, and [security](SECURITY.md) before designing access policy.
