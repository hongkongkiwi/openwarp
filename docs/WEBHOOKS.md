# Webhooks

Webhooks require the native server. Cloudflare Workers returns 501 for creation, test dispatch, delivery retry and incoming invocation. It does not accept work that has no dispatcher. `GET /api/capabilities` reports the runtime capability and API route catalog.

## Outgoing subscriptions

Workspace administrators create subscriptions at `POST /api/orgs/{oid}/webhooks` with `name`, an HTTPS `url`, `events` (an array of exact audit action names or `*`), optional `app_id`, and `enabled` (boolean). An application must belong to that workspace. Application scope can be updated, subject to the same workspace ownership validation; an update cancels outstanding deliveries. A workspace has at most 100 subscriptions.

List through the same collection URL. Read, patch or delete `/api/webhooks/{wid}`. Rotate the signing key through `POST /api/webhooks/{wid}/rotate`. Creation and rotation return `secret` once as `whsec_` followed by standard base64 encoding of 32 random bytes. Other responses exclude signing material. Keys are encrypted with the instance master key and subscription-specific associated data. Instance master-key rotation rewraps them without changing receiver signing keys. Master-dependent ordinary reads check the database key epoch before decryption. Master-dependent writes fence the captured key inside the same transaction as the mutation. A replica left on an older root returns 503 with `code: "epoch_stale"` instead of decrypting or writing. Webhook signing-key writes retain their legacy 409 master-key fingerprint fence. The native server also holds an asynchronous request barrier across rotation commit and in-memory key publication; that barrier is process-local, so drain other replicas and restart them with the current master key before restoring traffic.

Management requires workspace administrative permission and an unscoped credential. OAuth and explicitly scoped personal tokens additionally need `org:admin`. OAuth read and write scopes still apply. This scope is advertised for explicit consent; existing default scopes are unchanged.

Events contain only `id`, `type`, `timestamp`, `workspace_id`, `app_id`, `env_id` and `actor_id`. Audit detail and secret values are excluded. Matching subscriptions share a stable event ID. `POST /api/webhooks/{wid}/test` queues a metadata-only test event for an enabled subscription.

Signatures follow the Standard Webhooks framing. The exact persisted request bytes are signed as `webhook-id + "." + webhook-timestamp + "." + body`, using HMAC-SHA256 under the decoded key. Headers are `webhook-id`, `webhook-timestamp` (Unix seconds), and `webhook-signature` (`v1,` followed by base64 HMAC). Receivers should check timestamp freshness and deduplicate event IDs.

Create a subscription with `"asymmetric": true` to add Ed25519 asymmetric signing (Standard Webhooks `v1a`). The signing seed is encrypted with the instance master key and subscription-specific associated data; the public key is returned once at creation and rotation as `whpk_` followed by standard base64 of the 32-byte public key, and appears on every read of the subscription. Deliveries from an asymmetric subscription carry both signatures space-separated in the same header (`v1,<hmac> v1a,<ed25519>`), so a receiver can verify with either the shared secret or the public key alone. Rotating the signing key rotates both. Instance master-key rotation rewraps the encrypted seed; captured delivery signatures stay verifiable. The private signing key never leaves the server.

A subscription that keeps dead-lettering deliveries without an intervening success pauses itself after five consecutive dead-letters: it is set to `enabled: false` with `disabled_reason: "consecutive_dead_letters"`, outstanding deliveries are cancelled, and the pause is audited as `webhook.auto_disabled`. A workspace administrator re-enables it by patching `{"enabled": true}` (any management update clears the reason). This stops a dead destination from consuming the queue silently; the delivery error codes remain visible in the history.

Delivery is at least once. Audited local mutations commit their audit record, immutable metadata event and subscription target snapshot in the same database transaction. Fan-out into delivery queues happens afterward. A full subscription queue leaves its target in the outbox for a later poll; it does not discard the event. The outbox admits at most 10000 events. If admission or audit persistence fails, the originating local mutation rolls back. External provider effects cannot be rolled back with that transaction. Receivers must not infer exactly-once processing.

## Incoming integration triggers

Create or list through `/api/integrations/{iid}/webhooks`. Creation accepts a name and enabled flag, and returns the invocation URL and one-time signing secret. Patch or delete `/api/incoming-webhooks/{wid}`; rotate through its `/rotate` endpoint. Management requires the existing integration permission, credential scope and environment access.

Incoming triggers currently require server-encrypted environments. E2E and delegated environments are rejected rather than creating a server plaintext path or a runner job without revocation enforcement.

POST raw bytes to `/hooks/integrations/{wid}` with the same Standard Webhooks headers and framing. The timestamp window is 300 seconds in either direction. Bodies are limited to 64 KiB. Message IDs contain 1-128 ASCII letters, digits, underscores or hyphens. A repeated ID with the same body hash returns `200` with `duplicate: true`; changed bytes return 409. A new accepted receipt returns 202. There are at most 60 new accepted messages per minute per hook. Before subscription lookup or key decryption, a separate source-IP budget permits 180 requests per minute, including invalid signatures. Duplicate checks occur before quota charging.

The body cannot select integrations, destinations, configuration or values. A receipt requests a manual sync of its fixed integration, even when `auto_sync` is false. Accepted bodies up to 32 KiB are captured for operator inspection, encrypted with the instance master key and receipt-specific associated data, never stored in plaintext and never forwarded to the integration; larger admitted bodies run without a capture. Captures are erased when the instance master key rotates. Creator account, original credential validity, transport scope, role, environment access and workspace source IP policy are checked at admission and execution. Logging out or revoking that credential stops the hook; another login does not resurrect it. An authorized integration manager can POST `/api/incoming-webhooks/{wid}/reauthorize` to bind their current credential and source IP without changing the URL or signing key. Reauthorization cancels outstanding work and is audited. Incoming file-based `ssh` integrations are rejected until their blocking adapter supports cancellation; changing an existing target to `ssh` also prevents invocation and execution. Cloud SSH key-provider APIs are unaffected. Invocation source IP is also rechecked when work executes. Forwarded headers are trusted only under the server's configured trusted-proxy rules.

## History and scheduling

Outgoing history is `GET /api/webhooks/{wid}/deliveries`; incoming history is `GET /api/incoming-webhooks/{wid}/receipts`. Both return arrays, accept `limit` (default 25, maximum 100) and `offset` (maximum 100000), and expose IDs, status, attempts, HTTP status, elapsed milliseconds, update time, next attempt time and safe error codes. Incoming receipts also report the sync outcome message. Lists never include response bodies, request headers, provider credentials or captured payloads.

## Receipt inspection and replay

`GET /api/incoming-webhooks/{wid}/receipts/{rid}` returns one receipt's metadata plus its captured payload, decrypted on the fly for a manager of the integration. If the capture was erased by a master-key rotation, `body` is null and `body_available` is false. Receipt inspection never exposes signing keys, creator credentials or provider configuration.

`POST /api/incoming-webhooks/{wid}/receipts/{rid}/replay` requeues a delivered, failed or dead-lettered receipt for the same integration with the same stored bytes, resetting the attempt budget and outcome. Pending or in-flight receipts cannot be replayed, and the outstanding-work cap still applies. The delivery-time authorization checks (creator credential, environment mode, source IP, workspace lockdown) run again before any sync work.

Per-attempt outgoing records are available at `GET /api/webhook-deliveries/{did}/attempts` with the same administrator boundary and pagination. They include HTTP status, duration and safe failure codes, including expired claims, but no response bodies. Attempt records are retained for seven days.

Native polling uses conditional row claims, random claim IDs, 120-second leases and fenced finalization. Expired claims are recoverable. A process handles work serially, up to ten outgoing and ten incoming rows per poll. Failed work retries up to eight attempts with capped exponential delay plus jitter. The base delay is operator-tunable through `OPENWARP_WEBHOOK_RETRY_BASE_SECS` (default 5, clamped 0-3600); lower values converge faster for trusted local testing without changing the schedule shape. HTTP 429 and 503 can extend the delay through numeric Retry-After, capped at one hour. Failed and dead-lettered outgoing deliveries can be explicitly retried through `POST /api/webhook-deliveries/{did}/retry`, preserving the event ID and bytes. Retry resets the attempt budget.

Each hook admits at most 1000 outstanding rows. Completed, cancelled and dead-lettered rows are retained for seven days. Pending work is not silently pruned. Duplicate identity is retained with its receipt for that period, not forever.

Disable, update, rotate or delete invalidates outstanding work. An already transmitted request cannot be recalled. A change during an in-flight sync can likewise occur after a provider has received the request.

Every outgoing attempt resolves DNS, rejects prohibited address sets, pins the approved addresses, disables redirects and ignores ambient HTTP proxies. HTTPS is required unless the operator explicitly sets `OPENWARP_ALLOW_PRIVATE_EGRESS=1`. That override permits trusted local testing and broadens the network trust boundary.

Legacy `audit_webhook` settings and log-stream dispatch are disabled, including retry of their old pending records. Existing configuration and history remain readable for migration, but do not send. Replace them with signed subscriptions. This avoids retaining an unsigned, redirect-following forwarding path.

## Management through MCP

`api_routes` returns the same catalog as the authenticated capability endpoint. It lists explicit registered methods, not implicit HEAD/OPTIONS behavior or request schemas; disabled LDAP routes are omitted. `api_request` accepts `method`, a same-origin `/api/` path (including query parameters), optional JSON `body`, and optional `step_up` string. The latter forwards only `X-OpenWarp-Step-Up`. The only permitted `/api/auth/` routes are `/api/auth/step-up/start` and `/api/auth/step-up/verify`; their real identity and grant checks still apply. It invokes the real internal API router with the original credential and peer address. It cannot accept replacement headers, other authentication routes, absolute URLs or traversal segments. HTTP results appear in `structuredContent` and the equivalent text envelope as `{status, body}`; non-success results set `isError`.

An MCP OAuth token remains bound to its MCP audience. The internal dispatch marker is request-local and cannot be supplied as a header; using that token directly against REST remains unauthorized. Browser, step-up and client-crypto requirements still apply to their routes.

## Verification

The frozen HTTP suites were executed before backend edits: management had one pass and two failures, and webhooks had five failures. Subsequent results and remaining coverage are reported with the change; documentation is not evidence of a live provider delivery or a Workers build.
