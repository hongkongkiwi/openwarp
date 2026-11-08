# OpenWarp documentation

OpenWarp is a self-hosted secrets manager with a browser console, a Rust CLI, and an HTTP API. Start with a local instance, then choose the guides for your role.

## Start here

| Goal | Guide |
| --- | --- |
| Run OpenWarp and save your first secret | [Getting started](GETTING_STARTED.md) |
| Manage workspaces, applications, and environments | [Console guide](CONSOLE.md) |
| Inject secrets into a process or automate a deployment | [CLI reference](CLI.md) |
| See what is implemented and where the limits are | [Feature reference](FEATURES.md) |

## Operate an instance

| Goal | Guide |
| --- | --- |
| Deploy behind HTTPS and configure sign-in | [Deployment](DEPLOY.md) |
| Look up environment variables and defaults | [Configuration](CONFIGURATION.md) |
| Upgrade a database across releases, inspect the ledger, repair a failed run | [Schema migrations](MIGRATIONS.md) |
| Understand encryption, access control, and trust boundaries | [Security model](SECURITY.md) |
| Compare SSE, delegated and E2E key custody | [Encryption and key custody](ENCRYPTION.md) |
| Back up data and rehearse a restore | [Backup and restore](BACKUP.md) |

## Connect and extend

| Goal | Guide |
| --- | --- |
| Push secrets to another platform | [Integrations](INTEGRATIONS.md) |
| Review secret changes across environments | [Batched change requests](CHANGE-REQUESTS.md) |
| Exchange workload JWTs for scoped access | [Workload identity](WORKLOAD-IDENTITY.md) |
| Encrypt application data with workspace keys | [Transit encryption](TRANSIT.md) |
| Inject secrets into Kubernetes pods or worker nodes | [Kubernetes](KUBERNETES.md) |
| Configure workload JWT identity and folder restrictions | [Workload access](WORKLOADS.md) |
| Use workload, path-policy, rotation and transit endpoints | [API reference](API.md) |
| See the implemented features and limits | [Feature reference](FEATURES.md) |
| Understand the crates and data flow | [Architecture](ARCHITECTURE.md) |
| Build, test, and contribute changes | [Development](DEVELOPMENT.md) |

## Reading conventions

- Commands run from the repository root unless a guide says otherwise.
- Uppercase placeholders such as `ENV_ID` mean an identifier returned by your instance, not an environment's display name.
- Examples use dummy secret values. Never paste production credentials into an issue, screenshot, or shell history.
- The console calls an organisation a workspace. API routes and CLI commands use `org` for the same object.
- Server-side encryption (SSE) and end-to-end encryption (E2E) have different capabilities. Read the [security model](SECURITY.md) before choosing either.

This documentation describes the implementation in this repository. It does not claim complete compatibility with another secrets platform or replace an independent security review.

[Back to the project](../README.md)
