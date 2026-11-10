# Troubleshooting

[Documentation index](README.md) · [Configuration](CONFIGURATION.md) · [Deployment](DEPLOY.md)

Start with the failing operation, its HTTP status and the server revision. Do not change keys, disable access checks or delete a database to make an unexplained failure disappear.

## Collect safe evidence

Record the command or route, deployment target, response status and relevant server error. Redact bearer tokens, cookies, passwords, recovery kits, verification links, database URLs and secret values. An API error body or server log can contain sensitive information.

For a local instance:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/health
```

A healthy database check returns `{"ok":true,"service":"openwarp"}`. A `503` indicates the database check failed. A healthy response does not prove that mail, provider credentials, backups or every API operation works.

## Account setup and login

| Symptom | Check | Next action |
| --- | --- | --- |
| Verification mail does not arrive locally | Whether a mail provider is configured and whether the server is outside production mode | With no provider, the development server logs the rendered verification message. Open its link privately; do not share the log |
| Production signup cannot complete | Mail configuration, provider response and public URL | Configure a working provider or HTTP relay; development log delivery is not a production substitute |
| Login says to verify the email address | Account verification state | Complete verification or request a fresh link through the supported flow |
| Verification link is invalid | Expiry, prior use and whether it points to the correct instance | Request a new link rather than repeatedly opening the old one |
| Expected sign-in button is missing | `OPENWARP_AUTH_PROVIDERS`, provider credentials and build features | Compare [configuration](CONFIGURATION.md) with the running process, not just a local `.env` file |
| CLI login reaches the wrong server | Host setting and project configuration | Use `openwarp --host "$OPENWARP_HOST" login` with the intended origin |
| Browser login fails behind a proxy | Public origin, HTTPS, cookie settings, callback configuration and proxy trust | Align them with the actual external URL; do not disable secure cookies for a public deployment |

The first verified account becomes the instance owner. Bootstrap on a restricted network. Account registration alone is not proof that ownership has been claimed.

For Compose, a variable in your host shell or `.env` file is not automatically passed into the server container. See [deployment settings](DEPLOY.md#pass-deployment-settings-into-the-container).

## API access is denied

| Status or behavior | Likely area to inspect |
| --- | --- |
| `401` or missing Bearer token | Header format, expiry, revocation, issuer and token audience |
| `403` with a valid credential | Workspace membership, role permissions, token scopes, environment grants, network policy or lockdown |
| Environment token cannot list workspaces | Expected scoping; use `/api/me` and the permitted environment's metadata route |
| `428` / `step_up_required` | The action needs additional verification through a supported interactive flow |
| `429` | Request frequency and rate-limit behavior |
| `501` | Native-only feature or build option absent on the running target |

Do not replace an environment-scoped token with an owner credential just to bypass a failure. Identify the missing permission or wrong target first. An IP allowlist also depends on correctly configured proxy peers; trusting arbitrary forwarded headers is unsafe.

See [API authentication](API.md#base-url-and-authentication) and [security boundaries](SECURITY.md#authorisation-boundaries).

## A secret is missing or different

1. Confirm the instance, workspace, application, environment ID and path.
2. In the console, check whether the edit is still a draft. Select Deploy changes only when you intend to persist it.
3. Check for a personal override. Compare shared values using the CLI's base-export option or the API's `?base=1` export.
4. Check the secret type. Sealed values are intentionally omitted from plaintext exports and normal reads.
5. Check encryption mode. E2E values need an authorised client key and local decryption, not the normal SSE export path.
6. Check whether duplicate keys exist at different paths. Some convenience clients select the first match; others reject ambiguity.

Exports and `get` commands reveal plaintext. Use dummy values while diagnosing, and do not paste their output into an issue.

## Provider sync fails after a successful deploy

A local secret write and a remote provider update are separate operations. Inspect the per-integration result rather than treating HTTP success as proof of remote delivery.

Check the provider kind, destination identifiers, credentials, permissions, naming transformations and configured filters. Sealed values and personal overrides are not normal sync inputs. In mirror mode, review the adapter's deletion behavior before retrying.

Production egress controls can reject private or loopback destinations. Do not switch on `OPENWARP_ALLOW_PRIVATE_EGRESS` just to hide an error. Confirm that access to the destination is intended and constrain the network accordingly. Dynamic database leases also have an explicit host allowlist.

For delegated environments, verify the runner's credentials and environment-key grant, and inspect job state. The runner holds plaintext while syncing; its logs must not dump payloads. See [integrations](INTEGRATIONS.md) and [runner security](ENCRYPTION.md#runner-security).

## Startup, storage and keys

| Symptom | Safe diagnosis |
| --- | --- |
| Production startup rejects the master key | Check that the configured value is base64 for exactly 32 bytes and is actually passed to the process |
| Decryption fails after a restart or restore | Check that the database and original master key match. Do not generate a replacement key |
| SQLite cannot open its file | Check the URL, parent directory, ownership and writable storage |
| Database health check fails | Check connection settings, service availability and the server's database error without exposing credentials |
| KMS-wrapped data is unavailable | Check bridge availability, credentials, key ID and access to the original wrapping key |
| Migration fails | Preserve the error and database backup. Do not mark migrations applied manually to skip the failure |

SQLite is not the shared database for multiple native replicas. Follow the [PostgreSQL replica setup](DEPLOY.md#more-than-one-server) when scaling the included stack.

Do not assume HTTPS at the browser protects database traffic. Review the database driver's transport limits in [deployment](DEPLOY.md) and [security](SECURITY.md).

## Recovery kit or E2E access is lost

The instance master key cannot recover an absent client-held E2E private key. Look for the original recovery kit or another authorised holder who can grant access. A reset that discards the old key does not decrypt old E2E grants.

A recovery kit does not restore deleted database records. Preserve both the required key material and database backups, and rehearse the recovery process in isolation. See [backup and restore](BACKUP.md) and [key custody](ENCRYPTION.md#recovery-and-revocation).

## Console edits do not appear

The console is embedded in the Rust server. Editing `ui.rs` or `e2e.js` does not update an already running binary. Rebuild, restart the intended server, then reload the browser. Confirm the listening process is the one you rebuilt.

The Node console test reads source; it does not prove that a browser renders the changed page correctly. Check layout, keyboard behavior and browser errors separately. See [development](DEVELOPMENT.md).

## Workers behaves differently from native

Workers uses Durable Object SQLite rather than the native database connection setting. It has target-specific protocol limits, Secure cookies and different proxy handling. A native build with default features disabled is not by itself a Worker deployment.

Check the [Workers support and limits](DEPLOY.md#cloudflare-workers), Worker bindings and runtime secrets. A native-only endpoint returning `501` is not a reason to weaken authentication or replace the storage adapter.

## Report an unresolved problem

Include the source revision, native/Workers target, database backend, failing route or redacted command, expected result, observed status and the smallest safe reproduction using dummy data. State whether the failure occurs with a new disposable database or only an existing one, if you have actually tested that distinction.

Do not publish live credentials or exploit details. For suspected security vulnerabilities, agree on a private reporting channel with the maintainer as described in [security](SECURITY.md).
