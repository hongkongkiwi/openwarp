# Encryption modes and key custody

OpenWarp protects secrets at rest and in transit, but "the operator cannot read
the data" depends on the environment mode. This page states the boundary for
each mode so the guarantee is not overstated.

## Threat model

There are four parties to keep apart:

- The **vendor** who writes OpenWarp. A self-hosted instance has no phone-home
  path, so the vendor has no access by default.
- The **instance operator**, who runs the server and can change its code.
- The **cloud or KMS operator**, who controls the key service.
- A **database thief**, who has a copy of the database or a backup but not the
  running process.

At-rest encryption addresses the database thief and, with a KMS, a stolen disk.
It does not by itself stop the instance operator: a server that can decrypt to
serve an API or run a sync can be made to hand over plaintext.

## Encryption modes

Every environment has a `mode`.

### `sse` (managed, default)

The server generates an environment data key, wraps it with the instance root,
and decrypts secrets to serve the API and to run integrations.

- With `OPENWARP_KMS_URL` set, the root and each environment key are wrapped by
  an external KMS/HSM through the bridge described below. The database contains
  no usable root key.
- Without a KMS, the root is `OPENWARP_MASTER_KEY` or a generated key in the
  `meta` table. This is suitable for development, not for a deployment where the
  operator must be excluded.
- Secret ciphertext uses `ow2` framing: XChaCha20-Poly1305 with associated data
  binding `env_id`, `secret_id` and field. Value and comment rows are also bound
  to their version. Integration configs, lease values and proposal payloads
  carry their own record identifier in the associated data. Ciphertext cannot
  be moved between those records. Legacy rows without the `ow2` prefix remain
  readable.
- The lookup index is HMAC-SHA256 under the environment key, not a bare SHA-256.
- **Operator can read.** This mode is for automation, dynamic leases, PKI and
  any feature that needs server-side plaintext.

### `delegated`

The client generates the environment key. It wraps the key to itself and to a
customer-run sync runner. The server stores only ciphertext:

- `envs.mode='delegated'`, `env_key_wrapped` is empty.
- The creator's copy is in `env_keys`; the runner's copy is in
  `runner_env_keys`.
- Secrets are written through the E2E endpoint with client-side ciphertext.
- Integration configuration is sealed to the runner's X25519 key, not to the
  server. The server cannot read provider tokens either.
- A deploy or sync call queues a `sync_jobs` row. The runner polls
  `/api/runner/jobs`, decrypts in its own process, pushes to the provider, and
  reports the result. It can also return the managed names for mirror syncs.
- **The server cannot decrypt.** The operator can still modify the served web
  console (see the client-trust caveat).

### `e2e`

Same client-side encryption as delegated, without a runner grant. Humans decrypt
with their recovery kit in the CLI or browser. Server-side integrations are not
available. Use the console's key rotation or `openwarp e2e rekey` after removing
a member; revocation alone cannot erase a key the removed member already saved.

## Key hierarchy

```text
KMS/HSM root key (optional, external)
  └── instance root (meta.kms_root, wrapped by KMS)
       └── environment data key (envs.env_key_wrapped, `owkms:`)
            └── secret fields (`ow2:` ciphertext with AAD)

client password
  └── X25519 private key (wrapped with Argon2id + XChaCha)
       └── environment key (wrapped to the user or runner public key)
            └── secret fields (client-side XChaCha20-Poly1305)
```

The KMS bridge is provider-neutral. The server calls:

```text
POST {OPENWARP_KMS_URL}/wrap
  {"key_id":"...", "plaintext":"<base64>", "context":"env:<id>"}
  -> {"wrapped":"<provider blob>"}

POST {OPENWARP_KMS_URL}/unwrap
  {"key_id":"...", "wrapped":"<provider blob>", "context":"env:<id>"}
  -> {"plaintext":"<base64>"}
```

`OPENWARP_KMS_TOKEN` is sent as a bearer token when set. The adapter should pass
`context` to the provider's encryption context (AWS KMS), additional
authenticated data (GCP KMS), or the equivalent. `OPENWARP_KMS_KEY_ID` is stored
with each wrapped value so a key rotation can still unwrap old data; run
`POST /api/instance/rewrap` as the instance owner after switching key IDs.

The bridge URL may be `http://` as well as `https://`. With plain HTTP, the
wrap requests and unwrap responses carry plaintext root or environment keys
without transport encryption, and the bridge has no egress allowlist of its
own. Use HTTPS, a loopback listener, or a protected private network; treat
`OPENWARP_KMS_TOKEN` as a deployment secret with only the access the adapter
needs.

A fresh KMS deployment stores only `meta.kms_root`; the database then has no
usable root key. An existing deployment that already has `meta.master` adopts
that key under the KMS on first boot, stores the same root as `kms_root` and
deletes the plaintext `meta.master` row. TOTP secrets, OIDC client secrets, PKI
keys, lockbox values and environment keys all use that same root, so no record
needs re-encryption. Back up the KMS key: removing it makes the data unreadable
unless `OPENWARP_MASTER_KEY` still holds the same key.

### Production auto-unseal

On the native server, `OPENWARP_KMS_URL` permits production startup without
`OPENWARP_MASTER_KEY`. The first boot wraps a newly generated root, or adopts an
existing development root. Later boots unwrap that same persisted root. A failed
unwrap, an invalid root length or a missing bridge for a KMS-wrapped database
stops startup; none is a reason to create a replacement root.

Precedence is explicit: `OPENWARP_MASTER_KEY` when set; otherwise the persisted
KMS-wrapped `meta.kms_root`; otherwise a plaintext `meta.master` adopted under
the KMS; otherwise a newly generated root. Adoption of a plaintext development
root runs only when the master-key variable is absent. If `meta.master` and the
unwrapped `meta.kms_root` hold different roots, startup stops and neither row is
deleted: the database is not safe to serve and an operator must restore the
matching root or a backup. A KMS-wrapped database without `OPENWARP_KMS_URL` is
also fatal.
Test a restart with the configured bridge before removing any recovery copy.
The bridge credential is itself a deployment secret and must have access to the
stored key identifiers. This is not Shamir unseal or a recovery-share protocol.
The native bridge is unavailable on Workers, which still require an external
master-key binding.

Online instance-root rotation is refused when a KMS is configured or a wrapped
KMS root is persisted. Changing the external KMS key identifier and rewrapping
keys is a separate operation. The native SQLite root-rotation path also rewraps
transit wrapping keys and version-2 authentication keys in the same transaction.
A lifecycle lock prevents HTTP and maintenance work from persisting old-root
records during that operation. PostgreSQL and MySQL/MariaDB online rotation are
refused: OpenWarp does not provide an offline multi-replica root-rotation
command. Keep the existing
root until a coordinated migration has been designed and verified. Do not change
a startup key value as a substitute for re-encrypting stored key material.

## The honest limit on "we cannot read it"

1. **The console still uses the version 1 password flow.** The server exposes
   the client-derived protocol in [AUTH-PROTOCOL.md](AUTH-PROTOCOL.md) and the
   OAuth consent page uses it for version 2 accounts, but the console's own
   registration and sign-in forms still send the password, and the server uses
   it to wrap the private key. Version 1 accounts have the same exposure. A
   malicious operator can capture the password until clients move to version 2.
   For version 2 accounts the server holds only an authentication key it cannot
   use to derive the end-to-end wrapping key, so it can impersonate the account
   but cannot decrypt E2E data.
2. **The browser client is served by the server.** `/e2e.js`, `/auth-v2.js` and
   the console are delivered by the same process that could be compromised. A
   modified client can capture the password or keys regardless of the protocol.
   For high assurance, use the CLI or a signed native client and verify the
   client build. The console keeps the recovery kit and unwrapped environment
   key in page memory, a reload locks the environment, and staged plaintext is
   lost rather than cached.

## Recovery and revocation

- The recovery kit is the user's X25519 private key. Losing it loses access to
  `e2e` and `delegated` environments unless another grantee re-grants the key.
- There is no vendor or instance escrow key. That is intentional. An
  organisation that needs escrow should hold a recovery key split between
  administrators, not store it in OpenWarp.
- Removing a member deletes their wrapped key and sets `rekey_required`. Rotate
  the environment key from the console or with the CLI in one request so there
  is no window where the grant is gone but the ciphertext is not rotated.
  Rotation generates a new environment key, re-encrypts every secret, and
  rewraps the new key to every remaining grantee and the runner. The rewrite
  runs in one database transaction; a failed grant write rolls the whole
  rotation back. A rekey may remove grantees but cannot add one: grant access
  first, then rotate.
- A password reset does not bypass an enrolled second factor; it returns an MFA
  challenge instead of a session.

## Metadata leakage

In `sse` mode the current value, key name, comment, path and tags are encrypted,
and the lookup index is keyed. Run `POST /api/instance/encrypt-metadata` as the
instance owner once after upgrading to migrate rows written before that change.
Secret version history stores its path and tag columns in the clear, so treat the
version table as sensitive metadata even though its values and comments are
ciphertext. In `e2e` and `delegated` modes the server has no key, so it stores
whatever the client supplies; the CLI encrypts the path and sends `path_enc`.

## Runner security

The runner (`openwarp-runner`) is the only component that decrypts a delegated
environment for sync.

- It holds its X25519 private key in `OPENWARP_RUNNER_KEY`; inject it from a
  secret store, not a shell history.
- It authenticates with a runner token shown once at creation.
- It polls outbound. The server never initiates a connection into the customer
  network.
- Provider credentials live in the sealed integration config. Only the holder
  of the runner private key can open it, and the plaintext carries the
  integration context that the runner verifies against the job.
- A crash after claiming a job leaves it reclaimable after ten minutes. Each
  claim carries a random fencing token, so a late result from the superseded
  runner is rejected.
- Sealed secrets are excluded from job payloads, matching the server-side sync
  path.
- Plaintext exists in the runner's memory while a sync runs. Treat the runner
  host as a secrets-bearing system: dedicated container, no core dumps, no
  debug logging of job payloads.
- Only `webhook` and the four specialised connectors (`trigger`, `instabox`,
  `boat`, `daytona`) have runner connection tests. Other kinds sync but report
  "test not implemented".

## Features that remain managed-only

Dynamic Postgres leases, server-generated rotation values, PKI issuance,
approval workflows that inspect plaintext, and server-side search require the
server to read or create the secret. They stay in `sse` mode. A zero-knowledge
deployment gives those up or moves them into a client.

## Not yet implemented

- OPAQUE, which would also prevent the server from impersonating an account.
- A client-derived console registration and sign-in flow; the API and OAuth
  consent page support it, the console forms do not yet.
- Signed native clients and a reproducible console build.
- Automatic rekey on revoke; it is an explicit action because the server never
  holds the key.
- KMS key rotation orchestration beyond `POST /api/instance/rewrap`.

Report security issues privately to the maintainers rather than opening a
public issue with exploit details.
