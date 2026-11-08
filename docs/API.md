# API reference

The console, CLI and SDKs use the server's HTTP API. Protected requests use `Authorization: Bearer TOKEN` or a browser account-session cookie. OAuth, service and machine credentials are accepted only in the Authorization header, not in `ow_session`. A malformed Authorization header is rejected rather than falling back to a cookie. Workspace membership, role permissions, credential scopes and environment policy all apply. The console calls an organisation a workspace; API paths use `orgs`.

This page covers the workload, path-policy, static-rotation and transit additions. It is not an exhaustive route catalogue. See [features](FEATURES.md), [integrations](INTEGRATIONS.md), [CLI](CLI.md) and [workload access](WORKLOADS.md) for related behavior. JSON examples use placeholders, not usable credentials.

## Workload identity

| Method | Endpoint | Contract |
| --- | --- | --- |
| `GET` | `/api/orgs/{org_id}/identities/{identity_id}/workload` | Workspace owner; binding or `null` |
| `PUT` | Same path | Workspace owner; `{issuer,jwks_url,audience,subject,max_ttl_secs}`; TTL defaults to 300 and must be 1-300 seconds; the issued lifetime is the minimum of 300 seconds, this bound and the assertion's remaining lifetime |
| `DELETE` | Same path | Workspace owner; removes trust and revokes its issued tokens |
| `POST` | `/api/v1/machine/auth/workload/login` | `{identity_id,jwt}`; returns `{accessToken,expiresIn,identity_id,tokenType}` |

The same login endpoint also accepts `{trust_id,jwt}` for the inline-JWKS trusts managed at `/api/orgs/{org_id}/identities/{identity_id}/workload-trust`. That engine issues environment-scoped workload tokens and checks the trust on every request. Supply exactly one of `identity_id` or `trust_id`; ambiguous or missing selectors are rejected without trying another verifier. The external-JWKS `identity_id` engine below retains its revision-bound machine tokens.

Bindings require an existing workspace identity. Updating trust also revokes its issued tokens. Native exchange validates exact claims against configured public JWKS and consumes assertions once across the instance database. Kubernetes assertions use this same endpoint and must be fresh for each exchange. Workers exchange returns 501. See [workload access](WORKLOADS.md) for algorithms, claim bounds, network controls and Kubernetes refresh limitations.

## Path policy

`GET`, `PUT` and `DELETE /api/envs/{env_id}/path-policy/{role}` require the workspace owner. `PUT` accepts:

```json
{"rules":[{"prefix":"/payments/","capabilities":["read","write","delete"]}]}
```

Only explicit SSE environments and non-owner roles are supported. An empty rule array denies all paths; deleting the policy removes the additional restriction. Prefixes are canonical folder paths, not glob patterns. The policy narrows existing role, token and environment authority. Read filtering precedes decryption and reference resolution. A matching policy also restricts the principal's administrative and whole-environment API surface globally, not just in that workspace. See [path restrictions](WORKLOADS.md#restrict-secret-paths) before assigning a policy to an administrator.

## Rotation schedules

| Method | Endpoint | Contract |
| --- | --- | --- |
| `POST` | `/api/envs/{env_id}/rotations` | `rotations:write`; `{key,path,interval_secs,config}`; interval at least 60 seconds |
| `GET` | Same path | `secrets:read`; schedule metadata, not provider configuration or pending passwords |
| `DELETE` | `/api/rotations/{id}` | `rotations:write`; removes schedule |
| `POST` | `/api/rotations/{id}/run` | `rotations:write`; enables schedule and makes it due; returns `{scheduled:true,id}` |

A run response acknowledges scheduling, not remote success. Active execution claims cannot be reset by Run. Deleting a schedule, its environment or its application returns 409 while a pending password or execution claim exists. Static rotation is native-only; Workers reject its configuration. For `config.kind: "postgres-static"`, configuration requires a PostgreSQL admin `connection` URL and existing login `username`. The target must already exist as an unsealed string secret (`secret`, `config` or untyped) in an SSE environment; SSH keys and sealed values are rejected at creation and execution. The connection must parse as `sslmode=require`, except an explicit `sslmode=disable` to `127.0.0.1` or `::1` outside production, and the configured driver host must match `OPENWARP_ALLOWED_DB_HOSTS`. See [static rotation](INTEGRATIONS.md#static-postgresql-password-rotation) for recovery and network constraints.

## Transit

The established `/api/orgs/{org_id}/transit/keys` engine keeps its existing contract: `owt1:` ciphertext, required string `context`, `current_version` metadata, and an independent `transit:rewrap` permission and credential scope. Managing those keys also requires workspace administration. See [Transit](TRANSIT.md).

### Compatibility engine

The separate `/api/orgs/{org_id}/transit-compat/keys` engine below uses `compat_transit_keys` and `compat_transit_versions`. Keys and ciphertext are not interchangeable between engines. Its optional context, `key_version` responses and combined encrypt/decrypt rewrap permission remain distinct from the established engine.

Transit is workspace-scoped server-side payload encryption, separate from environment secrets. It does not export keys or store application plaintext. Owners/admins have their normal broad authority; other roles need explicit `transit:manage`, `transit:encrypt` or `transit:decrypt` permissions. The managed developer role does not receive these permissions. Credential scopes, when present, must also permit the operation. Environment-scoped credentials are refused. Rewrap requires both encrypt and decrypt authority in the role and, when scoped, in the OAuth/service credential. Service-token creation accepts explicit `transit:manage`, `transit:encrypt` and `transit:decrypt` scopes in addition to the existing secret scopes and `*`; these scopes do not grant missing role permissions.

| Method | Endpoint | Permission and JSON body |
| --- | --- | --- |
| `POST` | `/api/orgs/{org_id}/transit-compat/keys` | `transit:manage`; `{name}`; returns `{id,name,key_version}` |
| `GET` | Same path | `transit:manage`; list of `{id,name,created_at}` metadata |
| `POST` | `/api/orgs/{org_id}/transit-compat/keys/{key_id}/rotate` | `transit:manage`; returns `{id,key_version}` |
| `POST` | `/api/orgs/{org_id}/transit-compat/keys/{key_id}/encrypt` | `transit:encrypt`; `{plaintext,context}`; plaintext is base64; returns `{ciphertext,key_version}` |
| `POST` | `/api/orgs/{org_id}/transit-compat/keys/{key_id}/decrypt` | `transit:decrypt`; `{ciphertext,context}`; returns base64 `{plaintext}` |
| `POST` | `/api/orgs/{org_id}/transit-compat/keys/{key_id}/rewrap` | Both permissions; `{ciphertext,context}`; returns ciphertext under the latest version |

`context` is an optional string, defaulting to empty, limited to 1024 bytes. Plaintext is limited to 1 MiB. Ciphertext authenticates the workspace, key, version and exact context; changing any of them fails decryption. Ciphertext has an `owtransit:v1:` envelope and should be treated as opaque. Rotation retains old key versions for decryption; rewrap does not revoke the original ciphertext. There is no key-export, key-deletion or minimum-decryption-version endpoint in this implementation.

A dedicated wrapping key protects each transit key's versions. Non-KMS instance master-key rotation rewraps those wrapping keys without changing transit ciphertext. Online root rotation waits for active HTTP and maintenance operations before taking its snapshot. It atomically rewraps environment keys, transit wrapping keys, v2 authentication keys, configured LDAP passwords and other stored root-encrypted state; outstanding emailed-code challenges are invalidated. Online root rotation covers both Transit stores and retains the established engine's root-generation fence and checked transaction. It is limited to single-process SQLite; PostgreSQL and MySQL return 409 because process-local gates cannot coordinate other replicas. Those deployments must keep the current root until a coordinated offline procedure is available. Master rotation is refused when KMS is configured or persisted KMS root state exists. Back up the database and preserve its matching root custody; see [encryption](ENCRYPTION.md).
