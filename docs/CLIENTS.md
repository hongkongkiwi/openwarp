# Clients and automation

[Documentation index](README.md) · [API guide](API.md) · [CLI reference](CLI.md)

Choose a client by the operation you need and its documented behavior. The repository contains multiple client implementations; matching language names do not mean matching interfaces or coverage. This page does not imply that packages have been published to a registry or that every client covers every route.

## Choose a connection

| Need | Use | Reference |
| --- | --- | --- |
| Inject secrets into a local process | Rust CLI | [CLI commands](CLI.md) |
| Call the API from application code | A language client or direct HTTP | [Client inventory](#language-clients) · [API](API.md) |
| Manage applications and secrets as infrastructure | Terraform provider | [Terraform](#terraform) |
| Export configuration during a GitHub Actions job | Export action | [Action README](../action/README.md) |
| Deliver secrets to Kubernetes workloads | CLI init-container pattern or ESO webhook bridge | [Kubernetes](KUBERNETES.md) |
| Push values into another platform | Integration adapter | [Integrations](INTEGRATIONS.md) |
| Exchange a workload JWT for scoped access | Workload identity | [Trust configuration](WORKLOAD-IDENTITY.md) |
| Sync client-encrypted values | Customer-run delegated runner | [Encryption](ENCRYPTION.md#runner-security) |

## Language clients

Two client generations share the `sdk/` tree: convenience clients directly under `sdk/`, and OpenAPI-contract clients under `sdk/contract/`. Keep imports, constructor names and examples from the same generation.

| Location | Interface and runtime | Reference |
| --- | --- | --- |
| `sdk/typescript` | `OpenWarpClient`; ES2022 ESM, Node 18+ or Fetch-compatible runtime | [TypeScript README](../sdk/typescript/README.md) |
| `sdk/python` | `OpenWarp`; Python 3.8+, standard library | [Python README](../sdk/python/README.md) |
| `sdk/go` | `Client`; Go 1.21+, standard library, context-aware methods | [Go README](../sdk/go/README.md) |
| `sdk/rust` | Async `Client`; separate Cargo workspace with reqwest/rustls | [Rust README](../sdk/rust/README.md) |
| `sdk/contract/typescript` | `OpenWarp`; global Fetch and native TypeScript stripping or a bundler | [Contract client README](../sdk/contract/typescript/README.md) |
| `sdk/contract/python` | `Client`; Python 3.10+, standard library | [Contract client README](../sdk/contract/python/README.md) |

The direct `sdk/` clients document convenience methods for identity, resources, secrets, exports, leases and audit. The `sdk/contract/` clients reference the OpenAPI contract and include server-backed tests. Neither directory's presence establishes release status or interoperability with an arbitrary server revision. Pin a reviewed source revision and run its documented checks against the server you intend to use.

### Differences that affect correctness

- The documented `sdk/typescript` and `sdk/rust` helpers reject ambiguous key matches across paths. The documented `sdk/python` and `sdk/go` helpers select the first match. Use an explicit path-aware API operation when names are duplicated.
- The `sdk/` convenience setters document sending empty tags, which clears existing tags on update. Do not treat them as metadata-preserving patches.
- Missing keys, transport errors and invalid JSON do not have identical representations across languages. Use the chosen client's error type.
- Inspect deployment responses for sync errors even when HTTP succeeds.
- SDK error bodies and returned values may contain secrets. Do not log whole responses by default.

Use the instance base URL without `/api`, and use HTTPS outside local evaluation. Provision bearer tokens through a secret store rather than embedding them in code. Check the client's URL, timeout and redirect behavior before supplying a custom transport.

### Verification

Each client README lists its own checks and any verification limits. The Rust SDK is outside the root Cargo workspace, so `cargo test --workspace` does not test it. Mock-transport tests and tests against a local server are different kinds of evidence; neither demonstrates live provider behavior.

Run client tests serially with builds and other suites. Never point a destructive integration test at a production instance or a database you need to keep.

## Terraform

The provider tree is [`terraform-provider-openwarp/`](../terraform-provider-openwarp/README.md). It describes local development overrides, application/environment/secret/service-token resources and a secret data source, and CI runs its unit, live client and acceptance tests.

The provider READMEs state that the provider is not published to the Terraform Registry. A package name in an example is not evidence that a registry install is available.

Secret values and issued tokens can enter Terraform state. A `sensitive` attribute hides normal display but does not encrypt state. Restrict the state backend, backups, plans and CI artifacts accordingly. Importing a service token cannot recover its one-time plaintext value. Sealed secrets cannot be managed as ordinary readable values.

## GitHub Actions

The [export action](../action/README.md) reads an environment over HTTP and writes dotenv text or JSON to a file. It does not inject values into later steps automatically.

Use an environment-scoped token with the necessary read permission. Pin the action to a reviewed commit when consuming it from another repository. Keep value masking enabled, but treat masking as a log feature, not protection for the output file. Do not cache, commit or upload that plaintext file; remove it after use.

Consume exported configuration with a parser. Do not source or execute it as a shell script. Only trusted steps should have access to the token, file and job environment.

## Kubernetes

The [Kubernetes guide](KUBERNETES.md) covers workload consumption, including the External Secrets Operator (ESO) webhook bridge. ESO is a separate controller; the bridge is not a full OpenWarp Kubernetes operator.

Choose the environment and credential scope deliberately. Once copied into a Kubernetes Secret, a value is also subject to Kubernetes RBAC, storage encryption, backups and pod access. Deleting it in OpenWarp does not itself erase every consumer's copy.

## Automation and encryption modes

Ordinary export clients consume server-decrypted values. E2E environments require a client that implements local key handling and decryption; a generic HTTP client cannot turn ciphertext into plaintext. Delegated environments use a runner with an explicit environment-key grant for provider sync.

See [encryption and key custody](ENCRYPTION.md) before choosing an SDK, runner or export-based integration for a client-encrypted environment.
