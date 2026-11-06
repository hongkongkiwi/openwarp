# Security model

OpenWarp protects secrets at rest and in transit, but "the operator cannot read
the data" depends on which encryption mode an environment uses. This page
states the boundary for each mode so the guarantee is not overstated.

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
serve an API or run a sync can be made to hand over plaintext. That requires a
different design, described below.

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
- **Operator can read.** This mode is for automation, dynamic leases, PKI and
  any feature that needs server-side plaintext.

### `delegated`

The client generates the environment key. It wraps the key to itself and to a
customer-run sync runner. The server stores only ciphertext:

- `envs.mode='delegated'`, `env_key_wrapped` is empty.
- The creator's copy is in `env_keys`; the runner's copy is in
  `runner_env_keys`.
- Secrets are written through the E2E endpoint with client-side ciphertext.
- Integration configuration is sent to the server when the integration is
  created, then stored sealed to the runner's X25519 key. The server sees the
  config during creation; at rest, only the runner can open it.
- Test and Sync calls queue a `sync_jobs` row; a secret deploy updates the
  ciphertext and the next sync picks it up. The runner polls
  `/api/runner/jobs`, decrypts in its own process, pushes to the provider, and
  reports the result. It can also return the managed names for mirror syncs.
- Members with `secrets:write` can list runner names and public keys (never
  tokens) so they can wrap an environment key. Only organisation admins create
  or delete runners.
- **The server cannot decrypt.** The operator can still modify the served web
  console (see the client-trust caveat).

### `e2e`

Same client-side encryption as delegated, without a runner grant. Humans decrypt
with their recovery kit in the CLI or browser. Server-side integrations are not
available. Use the CLI `openwarp e2e rekey` after removing a member; revocation
alone cannot erase a key the removed member already saved.

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

A fresh KMS deployment stores only `meta.kms_root`; the database then has no
usable root key. An existing deployment that already has `meta.master` adopts
that key under the KMS on first boot, stores the same root as `kms_root` and
deletes the plaintext `meta.master` row. TOTP secrets, OIDC client secrets, PKI
keys, lockbox values and environment keys all use that same root, so no record
needs re-encryption. If `OPENWARP_MASTER_KEY` is also set and differs from the
stored master, the server refuses to boot rather than wrapping the wrong root.
After adoption the KMS is the only root: removing it makes the data unreadable
unless `OPENWARP_MASTER_KEY` still holds the same key. Back up the KMS key.

## The honest limit on "we cannot read it"

Two gaps remain between the current implementation and a malicious-operator
guarantee:

1. **Version 1 accounts still send the password.** New accounts, invites,
   password resets and the OAuth consent page use the client-derived protocol in
   [AUTH-PROTOCOL.md](AUTH-PROTOCOL.md): the password and wrapping key stay in
   the browser, and the server stores only an authentication key it cannot use
   to decrypt end-to-end data. Version 1 accounts keep the old password login
   until they reset their password (which upgrades them). A malicious operator
   can still impersonate a version 2 account because it holds the authentication
   key, but it cannot derive the wrapping key.
2. **The browser client is served by the server.** `/e2e.js`, `/auth-v2.js` and
   the console are delivered by the same process that could be compromised. A
   modified client can capture the password or keys regardless of the protocol.
   For high assurance, use the CLI or a signed native/desktop client, and verify
   the client build. The CLI already keeps its tokens in the OS credential store
   and decrypts E2E values locally. The console editor follows the same rule:
   the recovery kit and unwrapped environment key stay in page memory, a reload
   locks the environment, and staged plaintext is lost rather than cached.

For version 2 accounts, `delegated` and `e2e` protect the data from a stolen
database, backup, disk or server that only sees protocol traffic. They do not
protect against an operator who can replace the client code. Version 1 accounts
retain the old exposure until migrated. The console writes E2E and delegated
ciphertext only through `PUT /api/envs/:id/e2e/secrets`;
`GET /api/envs/:id/secrets` returns 409 for these environments, which is what the
browser acceptance test asserts. A delegated environment is edited with the same
in-memory editor, and rotation wraps the new key to every grantee and to the
runner. New apps follow the instance's managed or delegated policy; the choice
changes only where future environment keys are generated, never existing ones.

## Recovery and revocation

- The recovery kit is the user's X25519 private key. Losing it loses access to
  `e2e` and `delegated` environments unless another grantee re-grants the key.
- There is no vendor or instance escrow key. That is intentional. An
  organisation that needs escrow should hold a recovery key split between
  administrators, not store it in OpenWarp.
- Removing a member deletes their wrapped key and sets `rekey_required`. Run
  `openwarp e2e revoke --env <ENV_ID> --email <ADDRESS>` to remove the grant and
  rotate in one atomic request (`remove_user` on the rekey endpoint), so there is
  no window where the grant is gone but the ciphertext is not rotated. Rotation
  generates a new environment key, re-encrypts every secret, and rewraps the new
  key to every remaining grantee and the runner. `openwarp e2e rekey` remains for
  a grant that was already removed. Old history rows are replaced because they
  are encrypted under the old key. The rewrite runs in one database transaction;
  a failed grant write rolls the whole rotation back. A rekey may remove
  grantees but cannot add one: grant access first, then rotate.
- A password reset does not bypass an enrolled second factor; it returns an MFA
  challenge instead of a session.

## Metadata leakage

Secret names, paths, tags and key hashes are metadata. In `sse` mode the value,
key name, comment, path and tags are all encrypted, and the lookup index is
HMAC-SHA256 under the environment key rather than a bare SHA-256. A database
thief without the environment key can neither read the metadata nor test guesses
against the index. New writes do this automatically; run
`POST /api/instance/encrypt-metadata` as the instance owner once after upgrading
to migrate existing rows. In `e2e` and `delegated` modes the server has no key,
so it stores whatever the client supplies. The CLI encrypts the path and sends
`path_enc` and the endpoint rejects a put or rekey without it; the key hash
remains a client-supplied lookup value.

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

- OPAQUE or client-derived authentication.
- A libsodium or audited WebCrypto client in place of the hand-written
  `e2e.js` X25519.
- Signed native clients and a reproducible console build.
- Automatic rekey on revoke; it is an explicit CLI action because the server
  never holds the key.
- KMS key rotation orchestration beyond `POST /api/instance/rewrap`.

Report security issues privately to the maintainers rather than opening a
public issue with exploit details.
