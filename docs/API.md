# HTTP API

[Documentation index](README.md) · [Clients](CLIENTS.md) · [Security model](SECURITY.md)

Use the HTTP API for application access and automation. The console calls them workspaces; the API calls them organisations and uses `/api/orgs`. Resource identifiers are opaque strings, not display names.

The machine-readable reference is [`openapi.json`](../openapi.json). This guide explains authentication, common requests and operational boundaries; it is not an exhaustive endpoint schema. Consult the specification for the operations it documents and the focused guides for protocol-specific surfaces. Do not infer that an undocumented route is absent or that a listed route is available on every deployment target.

## Base URL and authentication

Use your instance origin, without an appended `/api`, as the base URL. Production requests must use HTTPS. The local walkthrough listens at `http://127.0.0.1:8080`.

Send API credentials in the header:

```http
Authorization: Bearer <access-token>
```

Obtain an appropriately scoped credential through the console, CLI login, machine Universal Auth or [workload identity](WORKLOAD-IDENTITY.md). Browser cookies authenticate account sessions; they are not an alternative transport for scoped service or OAuth credentials.

| Credential | Typical consumer | Boundary |
| --- | --- | --- |
| OAuth access token | CLI or delegated API client | Consent scopes, audience and underlying account permissions |
| Service token | A service or deployment job | Assigned scope, application/environment restrictions and revocation |
| Machine identity token | Non-human workload | Identity role, grants and token lifetime |
| Workload identity token | A job presenting a trusted JWT | Configured issuer/key, exact claims and one environment |
| Browser session | Interactive console | Account membership, policy and any required step-up verification |

Authentication is not authorisation. Workspace membership, role permissions, environment scope, network policy and emergency lockdown can still deny a request. `org:admin` does not imply secret-read permission. API and MCP audiences are separate.

## Check the caller

Provision `OPENWARP_TOKEN` through your secret store or a private session before running these examples. Do not paste a real token into a tracked script or shared shell history.

```bash
export OPENWARP_HOST='http://127.0.0.1:8080'
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${OPENWARP_TOKEN:?set a scoped access token}" \
  "${OPENWARP_HOST}/api/me"
```

An ordinary successful response includes identity fields such as `id`, `email` and `pubkey`, plus `env_scope`. An environment-scoped token cannot be assumed to list all workspaces or applications. Use `GET /api/envs/{env_id}/meta` for metadata about the environment it is permitted to access.

Deleting an environment removes its ordinary tokens. Eligible live, static human-owned read tokens retain a separate deletion receipt for at most 30 days, capped by the original expiry. A receipt accepts only the exact Bearer credential and `GET /api/me` (only `{"env_scope":"original-id"}`), `GET /api/envs/{original-id}/meta` (only `id`, `name`, `app`, `workspace` snapshots), and `GET /api/envs/{original-id}/export` with no query or exactly `?base=1`. Export returns 404 `{"error":"environment deleted","code":"environment_deleted"}`. Other paths, methods, HEAD and queries return 403; receipts cannot authenticate normal API or MCP operations or cookie sessions. Current creator status, unlocked membership, read permission, surviving parents, IP policy and emergency policy are checked before every receipt response. Invalid, expired or revoked receipts return 401; policy denials and unavailable checks are not deletion signals. Ordinary authenticated app token lists mark retained entries with `kind: "deleted_env_receipt"`; authorised creators or workspace owners/admins revoke them by original ID through `DELETE /api/tokens/{id}`, subject to current authentication and step-up checks.

The examples require a curl version with `--fail-with-body`. This preserves error bodies while returning a failing exit code for HTTP errors. Those bodies can contain sensitive details; do not copy them into public logs without review.

## Discover resources

For an identity permitted to enumerate the corresponding resources:

| Request | Purpose |
| --- | --- |
| `GET /api/orgs` | List workspaces visible to the caller |
| `GET /api/orgs/{org_id}/apps` | List applications in a workspace |
| `GET /api/apps/{app_id}/envs` | List an application's environments |
| `GET /api/envs/{env_id}/meta` | Read permitted environment metadata |
| `GET /api/envs/{env_id}/secrets` | Read secrets subject to permissions and secret type |

Encode identifiers as URL path segments. Prefer a client library over building URLs from untrusted strings. A path and a secret key together may be needed to disambiguate names within an environment.

## Wallet storage and reveal

In SSE environments, ordinary secret PUT accepts `wallet_private_key` and
`wallet_recovery_phrase`. Values are opaque UTF-8 strings: whitespace and
`${...}` text are preserved exactly. An existing wallet requires its exact
current type on every edit; omitted types, downgrades and switching wallet kinds
return 400. Ordinary records can be promoted to a wallet type.

Lists return wallet metadata with `value: null`. History masks all versions of a
current wallet, including versions before promotion, and always masks wallet-typed
versions. Export (including `base=1`), clone, wrapping, references, provider sync,
runner jobs and local AI value matching exclude wallet values. Personal overrides
are refused. Restore and point-in-time recovery refuse wallet type mismatches.

`GET /api/envs/{eid}/secrets/{sid}/reveal` returns `{"value":"..."}` for the
current shared wallet value only. It requires a live cookie or Bearer account
session, current environment and path access, `secrets:read`, and a single-use
`very_risky` grant in `X-OpenWarp-Step-Up`. Obtain that grant through the existing
step-up start/verify endpoints using emailed proof plus configured TOTP. Missing
proof returns 428; missing mail configuration returns 503. OAuth, service, machine
and workload credentials cannot reveal wallets, even with another account's
grant. Audit failure denies the response; successful reveals record
`wallet.reveal` without values or proof material. There is no signing endpoint
or server-side E2E wallet decryption.

## Export shared values

This request outputs plaintext. Run it only with dummy data during evaluation, or from a trusted consumer that can protect the output.

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${OPENWARP_TOKEN:?set a scoped access token}" \
  "${OPENWARP_HOST}/api/envs/${ENV_ID:?set the environment ID}/export?base=1"
```

The response is a JSON object:

| Field | Meaning |
| --- | --- |
| `text` | Newline-separated `KEY=value` text |
| `secrets` | Exported secret objects |
| `omitted_sealed` | Number of sealed values excluded from the export |

`base=1` (or `base=true`) skips the caller's personal overrides. Without it, the export can include those overrides. Deployments should choose deliberately rather than inheriting a person's local values.

Do not execute exported text as a shell script. The text representation is not a shell-escaping contract and may not fit multiline values or duplicate names across paths. Parse the structured `secrets` field where those distinctions matter. Normal plaintext export is not the client-decryption path for E2E environments.

## Writes and remote effects

Secret deployments, proposals, rotations and integration changes have different request schemas and permissions. Read the relevant operation in the specification before writing. Use [batched change requests](CHANGE-REQUESTS.md) when changes need review across environments.

A successful secret write can include per-integration sync failures. Check the deployment result as well as the HTTP status. Local persistence and remote provider writes are not a distributed transaction. Do not retry credential issuance, rotation or other side effects blindly after a timeout: the remote operation may already have happened.

## Errors and access recovery

Many errors use `{"error":"message"}`. Some authentication and verification flows include additional fields. Preserve the HTTP status and inspect structured fields instead of matching message text as a stable protocol.

| Status | What to check |
| --- | --- |
| `400` | Request schema, identifiers, field validation and supported operation |
| `401` | Missing, expired or revoked credential; token audience and login state |
| `403` | Membership, role, scopes, environment grants, IP policy or lockdown |
| `404` | Correct instance, resource ID and whether the resource still exists |
| `409` | The operation's conflict conditions; reread state before retrying |
| `428` | Additional verification required for a protected action |
| `429` | Rate limiting; reduce request frequency rather than retrying immediately |
| `501` | Feature unavailable on this build or deployment target |
| `503` from `/health` | Database connectivity or query failure |

A protected human-session action returns `428` with `step_up_required: true`,
`risk` (`two_factor` or `very_risky`), `totp_required` and `email_required`.
POST `{"risk":"very_risky"}` (or `two_factor`) to
`/api/auth/step-up/start` using the same account session. Its response names a
`challenge` and the required `methods`. POST that challenge plus `totp` and/or
`email_code` to `/api/auth/step-up/verify`. The returned `token` goes in
`X-OpenWarp-Step-Up` on one retry of the original action. Challenges last ten
minutes and allow five failed code attempts; grants last five minutes and are
consumed once. A very risky grant can satisfy a major action, not the reverse.

Both cookie and Bearer account sessions use this contract. Service, OAuth and
machine credentials are exempt from step-up and cannot complete its interactive
challenge. Their existing scopes and policy restrictions still apply. A grant does not replace authorization or revive a revoked
session. Handler authorization and local input validation precede consumption;
an operation can still fail afterwards on a concurrent conflict or external
provider failure, so do not retry effects blindly. A very risky action returns
`503` if mail is unconfigured. See [deployment](DEPLOY.md#step-up-verification)
for the action tiers and [troubleshooting](TROUBLESHOOTING.md) for access diagnosis.

## Dynamic lease renewal

`GET /api/leases/{id}` retains lease metadata and reports `renewable` only for an active, resolved local generic lease or a directly managed PostgreSQL lease with a permitted target. Expired, revoked, pending, corrupt, unsupported and worker-delivered leases report false. Provider credentials, including AWS STS sessions and OpenRouter keys, cannot be renewed in place.

`POST /api/leases/{id}/renew` requires the caller's environment scope, environment access and `leases:write` permission, plus the normal account-session step-up when applicable. `ttl_secs` follows issuance: an integer defaults to 3600 when absent or not an integer and is clamped to 60 through 2592000 seconds. The deadline is measured from renewal time. A successful response contains `id` and the exact committed `expires_at`; it does not replace the issued credential. PostgreSQL success requires acknowledgement of `ALTER ROLE ... VALID UNTIL` before the checked local update and audit commit. A conflict after that acknowledgement is an error requiring reconciliation, not proof that the remote change was undone. See [lease operation recovery](SECURITY.md#dynamic-lease-operation-recovery).

## Protocol and specialised surfaces

| Surface | Reference |
| --- | --- |
| Client-derived registration and login | [Authentication protocol](AUTH-PROTOCOL.md) |
| E2E envelopes, key grants and delegated runners | [Encryption](ENCRYPTION.md) |
| Workload JWT exchange | [Workload identity](WORKLOAD-IDENTITY.md) |
| Versioned application encryption | [Transit](TRANSIT.md) |
| Provider sync and connection configuration | [Integrations](INTEGRATIONS.md) |
| OAuth, MCP, SCIM, PKI, SSH certificates and dynamic leases | [Feature reference](FEATURES.md) and [security](SECURITY.md) |
| Workers availability and native-only protocols | [Deployment](DEPLOY.md#cloudflare-workers) |

## Contract maintenance

The server's shared route definitions live in [`crates/server/src/app.rs`](../crates/server/src/app.rs). The repository also includes [`scripts/check-openapi.py`](../scripts/check-openapi.py) for contract checks. A schema or route check does not establish runtime behaviour, permission correctness, live-provider compatibility or complete API coverage. Test the operations and failure cases your client depends on.

---

## Workload, path-policy, rotation and transit endpoints

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
