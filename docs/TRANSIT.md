# Transit encryption

Transit encrypts application-supplied bytes under versioned workspace keys. It is separate from environment secret storage and `POST /api/instance/rewrap`. The server holds transit keys and processes plaintext internally. This service is not E2E encryption and does not prevent the instance operator from decrypting data.

## Key management

An admin creates a key with `POST /api/orgs/ORG_ID/transit/keys` and a JSON `name`. Names accept 1-128 ASCII letters, digits, underscores, hyphens and dots. The response contains the key ID, name and current version; it never exports the key.

`GET` on that route lists key metadata. `POST /api/orgs/ORG_ID/transit/keys/KEY_ID/rotate` creates the next version. Older versions remain available to decrypt older ciphertext. There is no key-version retirement or key-export API.

Management requires both administrative authority and `transit:manage`. The managed owner/admin roles have wildcard permissions. Custom roles require each operation explicitly, and the developer role does not gain transit permissions by default.

## Encrypt, decrypt and rewrap

Each operation is a `POST` beneath `/api/orgs/ORG_ID/transit/keys/KEY_ID/`:

| Operation | Input | Output | Permission |
| --- | --- | --- | --- |
| `encrypt` | `plaintext` as base64, `context` as a string | `ciphertext`, `version` | `transit:encrypt` |
| `decrypt` | `ciphertext`, the original `context` | `plaintext` as base64, `version` | `transit:decrypt` |
| `rewrap` | `ciphertext`, the original `context` | `ciphertext` at the latest version, `version` | `transit:rewrap` |

Context is required, though an explicit empty string is accepted. It is limited to 1024 UTF-8 bytes. Plaintext is limited to 1 MiB after base64 decoding. The `owt1:` ciphertext authenticates its workspace, key, version and context. Moving it to another workspace/key or supplying a different context fails.

A rewrap-only role cannot call decrypt. Rewrap decrypts inside the server and encrypts under the latest key version, but its response never includes plaintext. This API does not promise cryptographic rewrapping without internal decryption. Saving an old ciphertext and its old key remains sufficient to decrypt it; rewrap does not erase earlier copies.

## Credential scopes

A service/PAT credential needs the explicit matching transit scope in addition to its principal's permission. Generic `secrets:read`, `secrets:write` and `*` scope strings do not substitute for an explicit transit action scope. An environment-scoped credential cannot use transit. Workload tokens are denied transit entirely.

Browser sessions use their workspace role permissions. OAuth credentials without the explicit transit scope are denied; the ordinary CLI OAuth registration does not request transit scopes. Audit records contain key/action/version metadata, not plaintext, ciphertext or context contents.

## Master rotation and replicas

Transit key versions are wrapped under the instance master with authenticated workspace/key/version metadata. Native master rotation rewraps them in the same checked transaction as existing master-wrapped records. An in-process lifecycle lock and persisted generation fence detect transit key changes during preflight. A stale replica refuses transit operations until it restarts with the matching master key.

Coordinate master-key changes across replicas and update `OPENWARP_MASTER_KEY` before restarting. This mechanism does not establish that every other master-encrypted feature has cluster-wide rotation coordination. Back up the database and matching master key, then rehearse a restore.

## Verification limits

SQLite and PostgreSQL tests cover permission separation, tenant/context binding, concurrent version rotation and fresh-state recovery after master rotation. The local Workers smoke test exercises key creation, rotation, decryption and rewrap. The recovery test recreates database connections and application state, not an operating-system process; production replica coordination still needs a deployment-specific rehearsal.

[Encryption and key custody](ENCRYPTION.md) | [Security model](SECURITY.md)
