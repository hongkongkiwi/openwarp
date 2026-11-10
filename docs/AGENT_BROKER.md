# Agent credential broker

The agent broker lets an agent call approved HTTP operations or remote MCP tools without receiving the upstream bearer token. OpenWarp holds the token, checks a short-lived broker session, and authenticates the upstream request.

The broker does not isolate an agent's operating system or make its permitted actions harmless. An agent can misuse an allowed operation or receive sensitive data in its result. Keep the control-plane login and any other secret-reading credentials outside the agent's sandbox.

## Boundaries

The broker uses separate credentials and endpoints from the secret-management API:

| Interface | Purpose |
| --- | --- |
| `/api/orgs/{org_id}/broker/*` | Human administrators configure services, approve sessions, revoke access and read broker audit records |
| `POST /api/broker/http` | An agent performs a configured HTTP operation |
| `POST /api/broker/mcp` | An agent calls an approved remote MCP tool through OpenWarp |
| `POST /mcp` | The existing secret-management MCP, which can return secret values |

Do not connect an agent to the existing `/mcp` endpoint when the requirement is to withhold secret values. Broker sessions cannot authenticate the normal API or that endpoint.

Broker execution requires the native server and an SSE environment. Cloudflare Workers return `501` for session issuance and execution. E2E and delegated environments are rejected: the broker does not add a server-side plaintext path for client-encrypted secrets. Delegated-runner brokering is not supported.

## Configure a service

Use an active, verified human account session with workspace administrative authority. Service tokens, machine tokens and OAuth access tokens cannot configure this initial control plane. Cookie-authenticated mutations also require a matching `Origin`.

A service binds one environment and one credential secret. The credential must be a live, ordinary shared secret in that environment. Sealed values and personal overrides are not credential sources. Give the upstream credential only the permissions the configured operations need.

Create a service with `POST /api/orgs/{org_id}/broker/services`:

```json
{
  "name": "Issue lookup",
  "env_id": "ENV_ID",
  "kind": "http",
  "credential_secret_id": "SECRET_ID",
  "enabled": true,
  "policy": {
    "allowed_member_ids": ["USER_ID"],
    "auth": {"type": "bearer"},
    "operations": [{
      "id": "lookup_issue",
      "url": "https://api.example.com/v1/issues/lookup",
      "method": "POST",
      "privileged": false,
      "input_schema": {
        "type": "object",
        "properties": {"issue": {"type": "integer", "minimum": 1}},
        "required": ["issue"],
        "additionalProperties": false
      },
      "response_fields": {"id": "/id", "state": "/state"}
    }]
  }
}
```

The example domain is a placeholder, not a supported provider integration. Replace the fixed URL and schemas with an endpoint you control and have reviewed.

URLs must use HTTPS on port 443, with a hostname rather than a literal IP address. Userinfo, query strings and fragments are rejected. The agent cannot change the URL, path, method or headers. HTTP operations support `GET` with empty arguments and `POST` with validated JSON arguments. Authentication supports bearer tokens only.

Input schemas describe a flat object of scalar properties. Unknown properties and unsupported schema keywords are rejected. Strings have a bounded length. Integer bounds must be JSON integers and are compared exactly across signed and unsigned 64-bit values. For `number` schemas, integer arguments and bounds must be within -9007199254740992 to 9007199254740992; use `integer` for larger exact integers. Configure numeric limits where the operation needs them; an integer type alone is not a useful spending or resource limit.

`response_fields` maps local field names to JSON pointers in the upstream response. Only bounded scalar values can be returned. Omit the map or use `{}` to return no upstream data. Missing fields, objects, arrays and invalid output fail rather than falling back to the raw response.

List services with `GET /api/orgs/{org_id}/broker/services`. Replace a service with `PUT /api/orgs/{org_id}/broker/services/{service_id}`, including its current `expected_revision` and the full service configuration. Updating or disabling a service invalidates sessions for the previous revision. `DELETE` disables/removes access without deleting audit history.

## Approve a session

The subject must be an allowed member with current access to the environment and the `broker:use` permission. This permission does not grant `secrets:read` and is not added to the built-in developer role. A human administrator approves the service and exact capability IDs:

```text
POST /api/orgs/{org_id}/broker/sessions
```

```json
{
  "service_id": "SERVICE_ID",
  "subject_user_id": "USER_ID",
  "capabilities": ["lookup_issue"],
  "approved_privileged_capabilities": [],
  "ttl_seconds": 300
}
```

The response contains an opaque `owb_` token once. OpenWarp stores its hash, not the token. The default lifetime is 300 seconds; accepted lifetimes are 1-900 seconds. Sessions cannot be refreshed.

Pass only this broker token to the agent's MCP client or HTTP client. It remains a credential: someone who steals it can exercise its capabilities until access is denied or it expires. Keep it in the client's protected authentication configuration rather than pasting it into model messages.

A capability marked `privileged:true` also needs its ID in `approved_privileged_capabilities`. This approval applies for the session's lifetime. It is not per-invocation confirmation, a two-person approval or protection against a misleading approval request. Do not approve broad destructive operations merely because the upstream token stays hidden.

List session metadata with `GET /api/orgs/{org_id}/broker/sessions`. Revoke a session with `DELETE /api/orgs/{org_id}/broker/sessions/{session_id}`. Each invocation checks current session, service revision, subject access and issuing administrator authority. Revocation cannot undo an upstream action already dispatched.

Deleting an environment stops its broker execution. Workspace administrators can still inspect the retained broker records, revoke sessions and disable the historical service. This access remains scoped to the workspace; it does not restore the deleted environment or its credentials.

## Call an HTTP operation

Send the broker token as a bearer credential to `POST /api/broker/http`:

```json
{"operation":"lookup_issue","arguments":{"issue":42}}
```

The session selects the service and environment. Successful responses contain a request identifier and only the approved projection:

```json
{"request_id":"REQUEST_ID","data":{"id":42,"state":"open"}}
```

The agent cannot use this endpoint to retrieve the credential, create a new session or change the service policy.

## Connect a remote MCP service

Create a service with `kind:"mcp"`. Its policy has a fixed `endpoint` and `tools` instead of HTTP `operations`:

```json
{
  "allowed_member_ids": ["USER_ID"],
  "auth": {"type": "bearer"},
  "endpoint": "https://tools.example.com/mcp",
  "tools": [{
    "id": "lookup_issue",
    "name": "issues_get",
    "privileged": false,
    "input_schema": {
      "type": "object",
      "properties": {"issue": {"type": "integer", "minimum": 1}},
      "required": ["issue"],
      "additionalProperties": false
    },
    "response_fields": {"id": "/id", "state": "/state"}
  }]
}
```

The agent uses `lookup_issue`; OpenWarp maps it to the exact upstream name `issues_get`. Output pointers are relative to the upstream result's `structuredContent`. OpenWarp does not expose upstream discovery descriptions or automatically adopt tools.

Configure the agent's remote MCP connection to `/api/broker/mcp`, with the broker token in its authorization header. The endpoint supports protocol `2025-06-18` and the methods `initialize`, `notifications/initialized`, `ping`, `tools/list` and `tools/call`. Tool discovery is filtered by the session's capabilities. Direct calls to other tools and resource methods are rejected, even if the client skips discovery.

Upstream support is limited to JSON-response Streamable HTTP with structured tool results. SSE-only upstreams, legacy HTTP+SSE, stdio, sampling, elicitation and resource forwarding are not supported. Upstream session identifiers stay inside the broker invocation. Errors never fall back to raw upstream messages or text results.

## Transport and audit

The native broker resolves and checks destination addresses, rejects private and special-use destinations, and pins the checked addresses for the connection while retaining TLS hostname verification. It does not use the general private-egress override. Redirects and ambient proxies are disabled. The broker does not retry requests, because a failed response does not prove an upstream mutation failed.

Limits are 32 KiB for invocation bodies, 64 KiB for service configuration, 256 KiB for an upstream response, 64 KiB for projected output and 15 seconds for the complete upstream operation, including MCP initialization. A service supports at most 32 capabilities.

Read metadata-only audit records at `GET /api/orgs/{org_id}/broker/audit`. Audit entries identify the session, service, capability, principals and decision. They do not store arguments, result bodies, credential values or authorization headers. The broker requires its audit writes to succeed before returning a successful result. A lost response or incomplete attempt still needs investigation; audit cannot roll back an external action.

## Confidentiality limits

Response projection reduces accidental disclosure but does not make a malicious upstream safe. A service that receives a credential can encode it into an otherwise permitted result field. Only approve trusted destinations and reviewed output fields. An approved MCP tool can also return prompt-injection content or other sensitive business data.

The upstream credential exists in the server's memory and is visible to the upstream service. The instance operator and a compromised broker remain inside the trust boundary. Protect the server and use least-privilege upstream credentials. This feature withholds credentials from the agent; it is not a guarantee that an authorized agent cannot cause damage.

[Security model](SECURITY.md) · [Encryption and key custody](ENCRYPTION.md) · [Documentation index](README.md)
