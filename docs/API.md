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

A run response acknowledges scheduling, not remote success. Active execution claims cannot be reset by Run. Deleting a schedule, its environment or its application returns 409 while a pending password or execution claim exists. Secret writes and deletion of that static rotation's target also return 409 until reconciliation; the scheduler alone may persist the pending password. Static rotation is native-only; Workers reject its configuration. For `config.kind: "postgres-static"`, configuration requires a PostgreSQL admin `connection` URL and existing login `username` distinct from the connection's admin username. The target must already exist as an unsealed string secret (`secret`, `config` or untyped) in an SSE environment; SSH keys and sealed values are rejected at creation and execution. The connection must parse as `sslmode=require`, except an explicit `sslmode=disable` to `127.0.0.1` or `::1` outside production, and the configured driver host must match `OPENWARP_ALLOWED_DB_HOSTS`. See [static rotation](INTEGRATIONS.md#static-postgresql-password-rotation) for recovery and network constraints.

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

## Personal secret health

These endpoints require a valid account session, not a service or OAuth access
token. The user comes from the session and must remain active and verified.
A nonempty Bearer credential takes precedence over the session cookie; an
invalid Bearer credential never falls back to the cookie. Session expiry and
revocation checks apply. Mutations reject cross-site origins.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /api/me/secret-health` | None | `{"api_key_set":false}` |
| `PUT /api/me/secret-health` | `{"api_key":"<32 hex characters>"}` replaces; `{"api_key":null}` clears | Only `api_key_set` |
| `POST /api/me/secret-health/email` | `{"email":"fixture@example.test","consent":true}` | `{"status":"found","breaches":["Example"]}` or `{"status":"not_found","breaches":[]}` |

Email checking uses the user's own paid HIBP key with the standard Core
`breachedaccount` endpoint and `truncateResponse=true`. It discloses the full
address to this server and HIBP. Explicit consent is required on every request.
Addresses are limited to 254 UTF-8 bytes. Attempts consume a per-user quota
of one per minute, including provider failures. No lookup results are stored.

Missing sessions return 401. Invalid input, missing consent or absent key
returns 400; cross-site mutations return 403. HIBP's 404 maps to `not_found`;
its 401/403 returns 502 with a key/subscription rejection message; 429 returns
429. Transport errors, redirects, malformed or oversized responses return 502.
Workers returns 501 for email checking because its HTTP facade does not yet
provide a bounded, redirect-safe credential transport. Settings remain usable.

The key is encrypted under the instance master key in per-user metadata and
included in master-key rotation. API responses never return the key. Do not
log request bodies or outbound URLs, which contain the disclosed email.

On a native server, credential saves, clears and read/decrypt snapshots share
a process-local gate with master-key rotation, acquired before rotation reads
the current key or metadata. It does not coordinate replicas or propagate a
new master key. Quiesce all other replicas before rotation and restart them
with the new key before serving requests again. This gate does not make
rotation of unrelated encrypted records transactional.

HIBP password checks have no OpenWarp backend endpoint: the bundled client module
computes SHA-1 locally for HIBP's range protocol, not for password storage.
Only an explicit opt-in permits its fixed Pwned Passwords request. SHA-1 here
is not a password KDF. See [the console guide](CONSOLE.md).

### Enzoic password-only BYOK

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /api/me/secret-health/enzoic` | None | `{"configured":false}` |
| `PUT /api/me/secret-health/enzoic` | `{"api_key":"...","api_secret":"..."}` replaces both; both values `null` clears | Only `configured` |
| `POST /api/me/secret-health/enzoic/password` | `{"prefix":"0123456789","consent":true}` | `{"candidates":[{"sha256":"<64 hex>","revealedInExposure":true,"exposureCount":7}]}` |

Keys and secrets must each be 1-256 visible ASCII characters without a colon.
They are stored as encrypted JSON in `enzoic_credentials:<user id>` metadata
under the instance master key and included in master-key rotation. Neither is
returned. The original HIBP settings response remains exactly `api_key_set`.

The browser hashes the exact UTF-8 password without normalization using SHA-256
and submits only its first ten lowercase hexadecimal characters. The relay
accepts only `prefix` and `consent`. It posts `{"partialSHA256":"<prefix>"}`
to `https://api.enzoic.com/v1/passwords` using HTTP Basic with the user's own
key and secret. The browser compares the full hash locally after validating
all candidates. Only an exact match with `revealedInExposure:true` is found.
An exact candidate marked false is `not_found`, not evidence of safety.

The native relay refuses redirects, has a ten-second request/body timeout,
and limits the body to 1 MiB and 1000 candidates. Only the three candidate
fields above are returned; raw breach records and results are not persisted.
Upstream 404 returns an empty candidate array. 401/403 return 502 with a generic
credential/subscription message; 429 returns 429; all other provider, parsing
and transport failures return 502. Each attempted lookup consumes an atomic
per-user quota of one per minute, including provider failures. Workers returns
501; settings work on both targets. Missing sessions, consent and credentials
follow the same 401/400 rules as HIBP; cross-site mutations return 403.

Operators must hold an applicable Enzoic subscription and comply with privacy
obligations and https://enzoic.com/terms-of-service. Those terms permit
application/account access but do not explicitly settle distribution specifics.
This implementation is not vendor-approved and does not resell access.

#### Enzoic credential pairs

Both POST relays require the same active account session, same-origin checks,
explicit consent, and the current user's encrypted Enzoic credentials. They
reject extra request fields. Native only; valid Workers requests return 501.
Emergency workspace or project lockdown blocks both routes before validation.

1. `POST /api/me/secret-health/enzoic/accounts` accepts
   `{"username_hash":"<64 lowercase hex>","consent":true}`. The browser hashes
   the lowercased exact email with SHA-256, without trimming. The native relay
   uses `GET https://api.enzoic.com/v1/accounts?username=<hash>` with HTTP Basic.
   A provider 404 returns `{"found":false}`. A 200 returns only `found:true`,
   a plain account `salt`, and `passwordHashesRequired` (`hashType`, optional
   plain legacy `salt`). No dates, exposure records or provider identifiers
   are forwarded.
2. The browser validates all requirements, computes legacy digests locally,
   then Argon2d of `lowercaseEmail + "$" + legacyHex` with the account salt,
   iterations 3, memory 1024 KiB, parallelism 2, and output 20 bytes. Only the
   first ten hex characters of each result leave the browser in
   `POST /api/me/secret-health/enzoic/credentials`:
   `{"partial_hashes":["<10 lowercase hex>"],"consent":true}`. The relay uses
   fixed `GET https://api.enzoic.com/v1/credentials` with repeated
   `partialHashes` parameters and HTTP Basic. It returns only
   `{"candidateHashes":["<40 lowercase hex>"]}`; 404 yields an empty array.
   Full equality is checked locally, never by the backend.

Supported hash types are 1 MD5, 2 SHA-1, 3 SHA-256, 13 MD5(password+salt),
14 SHA-512, 19 MD5(salt+password), 25 SHA-1(password+salt), 27 double MD5,
32 SHA-1(salt+password), 35 SHA-384, 37 SHA-256(salt+password), and
40 SHA-512(password+":"+salt). These are legacy dataset representations,
not recommendations for password storage. All digests use exact UTF-8 and
lowercase hex; no password normalization is performed.

Unknown hash types, encoded salts (including `$argon2`, `base64:` and `hex:`),
non-plain encoding metadata, malformed data or primitive failures invalidate
the entire lookup. No requirement is silently skipped. Limits: 32 requirements
or request prefixes, 1000 candidates, 1024 UTF-8 bytes per salt, 1 MiB response
body, ten-second request/body timeout, no redirects. Each stage has its own
atomic one-attempt-per-user-per-minute slot, including failures, so stage one
does not block stage two. Password-only quota is separate. Other provider and
transport errors return 502 (upstream 429 returns 429), never a clean result.

The email hash is a stable full identifier. Both OpenWarp and Enzoic receive
it and the password-derived prefixes; they allow correlation and guessing.
Plain emails, passwords, legacy hashes and full derived hashes are not sent
to the backend. Results are not persisted. `unavailable` means the complete
lookup could not be performed; `not_found` means no match in this dataset,
not evidence that a pair is unexposed.

Protocol/formula reference inspected: official JavaScript SDK
https://github.com/Enzoic/enzoic-javascript-client/tree/c51cfc56609b36ba41634b9b0ed75dbeb93d47ce
(`enzoic.js`, `src/hashing.js`, `src/passwordtype.js`). Local deterministic
primitive vectors and relay fixtures do not establish live provider acceptance;
no live Enzoic request was made.

### LeakCheck Public email hash lookup

`POST /api/me/secret-health/leakcheck` accepts only
`{"email_hash":"<24 lowercase hex>","consent":true}`. It requires an account
session and same-origin mutation checks, but no provider key or paid account.
The client trims and lowercases the email, hashes it with SHA-256 and sends
the first 24 hexadecimal characters. The server never receives the full email.
This stable identifier is not anonymous and can be tested against guesses.

The native relay uses only
`https://leakcheck.io/api/public?check=<prefix>`, without redirects, with a
ten-second request/body timeout and a 64 KiB body limit. It requires boolean
`success:true`, a nonnegative safe integer `found`, and at most 1000 `sources`
with bounded `name` and `date` strings. Only names are returned as
`{"status":"found","breaches":["Example"]}` or
`{"status":"not_found","breaches":[]}`. Contradictory counts/source presence,
malformed data, `success:false`, redirects and HTTP failures are unavailable
(502, or 429 for throttling), never a clean result. Raw provider errors are
not reflected. Workers returns 501.

Atomic database quota limits are one attempt per user per minute plus an
instance-wide shared-egress slot. The latter uses two whole-second clock ticks
to guarantee at least one second between attempts. Provider failures consume
quota; other instances with independent databases need their own coordination.
No results or hash identifiers are persisted in audit records. Operators must
avoid logging request bodies or outbound query strings.

Protocol source: https://docs.leakcheck.io/public-api/lookup.md. The docs specify
SHA-256 truncated to 24 characters; lowercase follows the official SDK. Taking
the first 24 characters is the conventional interpretation, not explicitly
demonstrated by the official example. Live compatibility remains unverified;
only mocked local fixtures were executed. Attribution: Powered by LeakCheck.

Contract source for HIBP: https://haveibeenpwned.com/API/v3. Password range response
handling was tested with local fixtures. Live provider calls and the Rust
email response path have not been executed during implementation.
