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

A successful response includes identity fields such as `id`, `email` and `pubkey`, plus `env_scope`. An environment-scoped token cannot be assumed to list all workspaces or applications. Use `GET /api/envs/{env_id}/meta` for metadata about the environment it is permitted to access.

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

A step-up response can include `step_up_required: true`. Supported interactive flows obtain a short-lived grant and send it as `X-OpenWarp-Step-Up`. This is not a signal to retry with a more privileged automation token. See [security](SECURITY.md) for protected actions and [troubleshooting](TROUBLESHOOTING.md) for access diagnosis.

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
