# Workload identity

A workload can exchange a signed JWT for a short-lived OpenWarp token without storing an OpenWarp client secret. An administrator configures the public signing keys and exact claims accepted for an existing machine identity. This is separate from Universal Auth, which still uses a client ID and secret.

## Configure trust

As a workspace admin, send `POST /api/orgs/ORG_ID/identities/IDENTITY_ID/workload-trust`:

```json
{
  "issuer": "https://issuer.example.invalid",
  "audience": "openwarp-production",
  "subject": "repo:example/project:environment:production",
  "jwks": {"keys": []},
  "env_id": "ENV_ID",
  "scopes": ["secrets:read"],
  "ttl": 300,
  "bound_claims": {"repository": "example/project"}
}
```

Replace the empty `keys` array with the issuer's public signing JWKS before submitting; the example is a shape, not an accepted configuration. Do not include private JWK fields. RSA RS/PS signatures, P-256 ES256 and P-384 ES384 are supported. Keys marked for encryption or non-verification operations are refused. The server does not discover or fetch signing keys. Rotate keys by revoking the trust and creating a replacement with the updated public JWKS.

The environment must belong to the workspace. Only an owner can configure trust for an admin-equivalent identity. TTL is 30-900 seconds, and scopes must be an explicit nonempty selection of `secrets:read` and `secrets:write`. The identity's role and environment grants still apply; trust configuration does not grant the identity broader access.

Issuer, audience and subject match exactly. Additional bound claims are strings or string arrays and match the configured JSON value exactly, including array order. They do not support wildcard patterns. Reserved JWT claims cannot be replaced through `bound_claims`.

List policies with `GET` on the same route. Revoke one with `DELETE /api/orgs/ORG_ID/identities/IDENTITY_ID/workload-trust/TRUST_ID`. Revocation invalidates issued tokens through live policy checks, not just expiry. Deleting the identity also invalidates its credentials.

## Exchange a proof

Send `POST /api/v1/machine/auth/workload/login` with `trust_id` and `jwt`. The response contains `accessToken`, `expiresIn`, `tokenType` and `identity_id`. Keep the JWT and response out of logs and shell arguments.

A proof must have a valid asymmetric signature and matching `iss`, `aud`, `sub` and bound claims. It must include integer `exp` and `iat` plus a nonempty `jti`. Its issue time cannot be more than 900 seconds old or over 30 seconds in the future; its lifetime cannot exceed one hour. `nbf` is enforced when supplied. The issued token expires no later than either the configured TTL or the proof itself.

A JWT identifier is consumed once per issuer across trusts. The issuer must issue a fresh identifier for every exchange. Dynamic key headers such as `jku` and `x5u` are refused. Exchange requests are rate-limited and the workspace IP allowlist applies using the peer address and configured trusted-proxy rules.

## Token boundaries

Workload tokens are restricted to their single environment. They can read secrets, exports and environment metadata with `secrets:read`, or deploy/import with `secrets:write`, subject to the identity's permissions and environment policy. Read-only access to E2E endpoints retrieves ciphertext and grants, not plaintext. The client still needs its private key.

Workload tokens cannot administer workspaces, create credentials, change grants, use transit operations or call MCP. They do not replace runner tokens or provide an SSH privileged-principal step-up.

## Deployment and verification limits

Exchange uses a checked transaction to consume replay state and mint the token together. Native SQLite, PostgreSQL and the Workers Durable Object backend implement this transaction. Rate-limit bookkeeping may be updated for failed attempts.

The regression suite exercises claim validation, replay, token scoping, revocation and peer allowlists. PostgreSQL concurrency and the local Workers runtime also exercise exchange and replay. These checks do not prove compatibility with a particular live issuer. Test a real issuer's JWT shape and its key-rotation procedure before deployment.

[Security model](SECURITY.md) | [CLI](CLI.md)
