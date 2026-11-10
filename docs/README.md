# OpenWarp documentation

Run a local instance, choose an encryption boundary, then connect the workloads that need your secrets.

[Project overview](../README.md) · [Local walkthrough](GETTING_STARTED.md) · [Troubleshooting](TROUBLESHOOTING.md)

## Choose a reading path

| You want to… | Read in this order |
| --- | --- |
| Evaluate OpenWarp | [Getting started](GETTING_STARTED.md) → [Core concepts](CONCEPTS.md) → [Console](CONSOLE.md) |
| Connect an application | [CLI](CLI.md) → [API](API.md) → [Clients and automation](CLIENTS.md) |
| Run an instance | [Security](SECURITY.md) → [Deployment](DEPLOY.md) → [Configuration](CONFIGURATION.md) → [Backup and restore](BACKUP.md) |
| Review key custody | [Encryption](ENCRYPTION.md) → [Authentication protocol](AUTH-PROTOCOL.md) → [Architecture](ARCHITECTURE.md) |
| Contribute a change | [Architecture](ARCHITECTURE.md) → [Development](DEVELOPMENT.md) → [Repository rules](../AGENTS.md) |

## Learn and use

| Guide | What it covers |
| --- | --- |
| [Getting started](GETTING_STARTED.md) | Local SQLite setup, account verification, first secret and process injection |
| [Core concepts](CONCEPTS.md) | Workspaces, environments, identities, drafts, encryption and recovery |
| [Console](CONSOLE.md) | Browser-based administration and secret editing |
| [CLI](CLI.md) | Login, project defaults, imports, exports, injection and specialised commands |
| [Troubleshooting](TROUBLESHOOTING.md) | Login, denied access, missing values, sync, storage and runtime failures |
| Deploy behind HTTPS and configure sign-in | [Deployment](DEPLOY.md) |
| Look up environment variables and defaults | [Configuration](CONFIGURATION.md) |
| Understand the self-hosted and enterprise plans | [Editions and licensing](EDITIONS.md) |
| Upgrade a database across releases, inspect the ledger, repair a failed run | [Schema migrations](MIGRATIONS.md) |
| Understand encryption, access control, and trust boundaries | [Security model](SECURITY.md) |
| Compare SSE, delegated and E2E key custody | [Encryption and key custody](ENCRYPTION.md) |
| Back up data and rehearse a restore | [Backup and restore](BACKUP.md) |

## Connect and automate

| Guide | What it covers |
| --- | --- |
| [HTTP API](API.md) | Bearer authentication, resource discovery, export, errors and contract boundaries, plus workload, path-policy, rotation and transit endpoints |
| [Clients and automation](CLIENTS.md) | SDK directory inventory, Terraform, GitHub Actions and client differences |
| [Integrations](INTEGRATIONS.md) | Provider configuration, sync options and destination-specific behavior |
| [Webhooks](WEBHOOKS.md) | Signed outgoing subscriptions and incoming integration triggers |
| [Webhook source review](WEBHOOK_REVIEW.md) | Inspected upstream webhook practices and limits |
| [Kubernetes](KUBERNETES.md) | Workload consumption and the External Secrets Operator webhook bridge |
| [Batched change requests](CHANGE-REQUESTS.md) | Review and apply changes across environments |
| [Workload identity](WORKLOAD-IDENTITY.md) | Exchange trusted workload JWTs for scoped access |
| [Workload access](WORKLOADS.md) | Configure workload JWT identity and folder restrictions |
| [Transit encryption](TRANSIT.md) | Encrypt application data using versioned workspace keys |
| [Assistant and security insights](AI.md) | Configure BYOK assistance and investigate security findings |

## Operate and secure

| Guide | What it covers |
| --- | --- |
| [Deployment](DEPLOY.md) | Native, Compose and Workers targets; bootstrap, proxies, migrations and upgrades |
| [Configuration](CONFIGURATION.md) | Environment variables and defaults |
| [Backup and restore](BACKUP.md) | Database backups, key preservation and recovery rehearsal |
| [Security model](SECURITY.md) | Trust boundaries, authorisation, credentials and operational controls |
| [Encryption and key custody](ENCRYPTION.md) | SSE, delegated and E2E modes; KMS bridge and runner boundaries |
| [Authentication protocol](AUTH-PROTOCOL.md) | Client-derived authentication and its limitations |

## Build and maintain

| Guide | What it covers |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Source map, storage, request flow and native/Worker separation |
| [Development](DEVELOPMENT.md) | Prerequisites, serial checks, browser verification and contribution rules |
| [Testing](TESTING.md) | Test layers, commands, fixtures, per-feature coverage matrix and acceptance scenarios |
| [OpenAPI document](../openapi.json) | Machine-readable contract for the operations it describes |

## Reading conventions

- Commands run from the repository root unless a guide says otherwise.
- Uppercase placeholders such as `ENV_ID` mean an identifier returned by your instance, not an environment's display name.
- The console calls an organisation a workspace. API routes and CLI commands use `org` for the same object.
- Examples use dummy values. Tokens, recovery kits, verification links and exported secrets must not enter issues, screenshots or shared logs.
- Server-side encryption (SSE), delegated encryption and end-to-end encryption (E2E) have different key-custody and automation boundaries.
- Native and Workers deployments have different protocol support. A listed feature is not a claim of availability on every build.
- An implemented adapter or endpoint is not evidence of live-provider verification. Follow each component's verification notes and test the paths you depend on.

These guides describe the implementation in this checkout. They do not claim complete compatibility with another secrets platform or replace an independent security review.
