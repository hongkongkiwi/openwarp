# Workload identity and scoped access

Machine identities can exchange signed JWT assertions for short-lived OpenWarp tokens on the native server. This is an OpenWarp API, not an OpenBao or Vault protocol implementation. Kubernetes uses the same JWT exchange; there is no TokenReview call or automatic cluster discovery.

## Configure trust

A workspace owner configures one binding per existing machine identity with `PUT /api/orgs/{org_id}/identities/{identity_id}/workload`:

```json
{
  "issuer": "https://issuer.example.com",
  "jwks_url": "https://issuer.example.com/keys",
  "audience": "openwarp",
  "subject": "system:serviceaccount:payments:api",
  "max_ttl_secs": 300
}
```

These are illustrative URLs, not provider defaults. Copy the issuer, signing-key endpoint and exact subject from your issuer configuration. `GET` returns the binding or `null`; `DELETE` removes it. Replacing or deleting a binding revokes tokens issued through that binding, including an exchange racing with the change. Universal Auth remains a separate login method.

Exchange an assertion with `POST /api/v1/machine/auth/workload/login`:

```json
{"identity_id":"IDENTITY_ID","jwt":"SIGNED_ASSERTION"}
```

The response has `accessToken`, `expiresIn`, `identity_id` and `tokenType: "Bearer"`. Use the access token in the Authorization header. Its authority is the machine identity's workspace role, narrowed by normal access checks. The issued lifetime is the minimum of 300 seconds, the binding's `max_ttl_secs` (1-300) and the assertion's remaining lifetime.

The assertion must have a `kid`, an asymmetric signature, exact `iss` and `sub`, and exactly one configured audience (a string or single-element array). Integer `exp` and `iat` are required. Assertions can span at most one hour, future `iat` is limited to 30 seconds, and `nbf` and expiration are enforced without an expiry grace period. Supported algorithms are RS256/384/512, PS256/384/512, ES256/384 and EdDSA with a matching public signing JWK. Symmetric keys, private JWK material and ambiguous key IDs are rejected.

Assertions are single-use across the instance database, including duplicate bindings. Replaying an assertion returns a conflict. Obtain a fresh assertion for every exchange. In particular, rereading the same Kubernetes projected service-account token does not make it reusable: workloads need a mechanism to request a fresh audience-bound token before each exchange. Do not assume kubelet's periodic file refresh matches OpenWarp's access-token lifetime. This guide does not claim an end-to-end Kubernetes controller integration.

JWKS retrieval uses the configured URL, not URLs from JWT headers. Native retrieval pins resolved public addresses, refuses redirects, and limits the whole fetch to 15 seconds, 256 KiB and 32 keys. Assertions are limited to 16 KiB. HTTPS is required unless the operator enables `OPENWARP_ALLOW_PRIVATE_EGRESS=1`, which also permits private HTTP endpoints. That override broadens outbound access for the instance; do not enable it merely to bypass a production trust configuration.

Workers return 501 for workload exchange because the bounded, address-pinned JWKS transport is native-only. Workers also do not support the native KMS auto-unseal bridge. See [configuration](CONFIGURATION.md) and [encryption](ENCRYPTION.md).

## Restrict secret paths

A workspace owner can put a role policy on an explicit SSE environment with `PUT /api/envs/{env_id}/path-policy/{role}`:

```json
{"rules":[{"prefix":"/payments/","capabilities":["read","write"]}]}
```

`GET` returns the rules or `null`. `DELETE` removes the policy and restores the normal role behavior. The owner role cannot have a policy. No policy means unchanged access; an existing policy with `rules: []` denies all secret paths. Policies allow matching prefixes, rather than subtracting denied prefixes. Capabilities are `read`, `write` and `delete`; they never grant permissions missing from the caller's role, token scopes or environment access.

Prefixes and paths must start and end with `/`. Policies reject dot segments, repeated slashes, percent encoding, backslashes and control characters. A `/payments/` rule includes child folders but not `/payments-other/`. Policies apply to stored secret paths before values are decrypted or reference maps are built. Lists, exports (including `base=1`), search, reuse checks and MCP reads omit disallowed values. Direct-ID operations check the current path; history filters historical paths, and restore also requires read access to the historical path. For a restricted principal, creating or changing a personal override requires role and path write access. Reading or deleting its own override requires read access to that path. Without a path policy, personal overrides retain the existing environment-access behavior. Bulk writes preflight all submitted paths.

The path rule is local to an environment and role. The safety restriction on operations is instance-wide for that principal: if any workspace membership or machine identity role matches a path policy, the principal is denied administrative and whole-environment operations even in another workspace where it is an admin or owner. This includes membership/role/token changes, integrations, rotation, leases, proposals, cloning, comparison, point-in-time restore, E2E key operations and live events. Browser cookies are subject to the same restriction. Remove the matching policy or use a separate unrestricted administrative account for those tasks.

Restricted principals retain only the explicitly allowed secret and discovery API routes and the MCP secret tools (`list_envs`, `list_secrets`, `get_secret`, `search_secrets`, `set_secret`, `delete_secret`). They cannot invoke arbitrary MCP tools. Automatic provider sync is suppressed for restricted writes, deletes and restores. A filtered subset is never sent as a whole-environment mirror; an unrestricted operator must sync separately.

## Other server-managed key operations

[Static PostgreSQL rotation](INTEGRATIONS.md#static-postgresql-password-rotation) changes an existing remote role and stores its password in an SSE secret on the native server. Workers reject this configuration. Pending passwords survive uncertain outcomes so retries reuse the same candidate. An uncertain execution retains a non-expiring claim; stop all workers and verify the remote operation has ended before following the documented manual claim recovery. [Transit](API.md#transit) encrypts application payloads under workspace keys with separate permissions. Neither feature provides client-held E2E encryption.

Online instance master-key rotation is limited to single-process SQLite. PostgreSQL and MySQL/MariaDB return a conflict because the process-local lifecycle and transit gates cannot coordinate replicas. Keep the existing root until a coordinated offline procedure is available. Rotation also returns a conflict while KMS is configured or a persisted KMS root exists. Do not replace the startup master key or remove KMS state to bypass this guard. Follow the key-custody and recovery requirements in [encryption](ENCRYPTION.md).

The examples here describe request contracts inspected in source. They are not evidence that a particular external JWT issuer or Kubernetes deployment was exercised.
