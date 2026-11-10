# Webhook source review

This review covers selected webhook security, dispatch, persistence and inspection code in five projects. It is not a whole-repository audit. No upstream code was executed. The observations inform an independent OpenWarp implementation, not a code port or a claim that OpenWarp already has these behaviors.

The revisions below were observed on 2026-11-07. Files were retrieved through GitHub's API from default branches before HEAD was recorded. Branch movement between file retrieval and revision recording was not independently excluded.

## F1. Webhook.site

Repository: [webhooksite/webhook.site](https://github.com/webhooksite/webhook.site), observed revision `96b7b4275b4481eedd8a3f052aa44642eb3b4ae2`. The actual [license](https://github.com/webhooksite/webhook.site/blob/96b7b4275b4481eedd8a3f052aa44642eb3b4ae2/LICENSE) is MIT, although repository metadata reported `NOASSERTION`.

Inspected code:

- [RequestController.php](https://github.com/webhooksite/webhook.site/blob/96b7b4275b4481eedd8a3f052aa44642eb3b4ae2/app/Http/Controllers/RequestController.php), lines 47-117: request storage precedes broadcast; request-count quotas and pagination metadata are explicit.
- [RequestStore.php](https://github.com/webhooksite/webhook.site/blob/96b7b4275b4481eedd8a3f052aa44642eb3b4ae2/app/Storage/Redis/RequestStore.php), lines 33-99: Redis hash storage refreshes expiry on lookup and storage; pagination loads and sorts the full hash in memory.
- [TokenController.php](https://github.com/webhooksite/webhook.site/blob/96b7b4275b4481eedd8a3f052aa44642eb3b4ae2/app/Http/Controllers/TokenController.php) and [routes.php](https://github.com/webhooksite/webhook.site/blob/96b7b4275b4481eedd8a3f052aa44642eb3b4ae2/app/Http/routes.php): UUID-addressed capture, inspection and deletion routes.

Adopt stable receipt IDs, explicit retention, capture limits and pagination metadata. OpenWarp must apply workspace permissions to inspection rather than rely on knowledge of a capture URL. Arbitrary headers and bodies are inappropriate default diagnostic storage for a secrets manager. Query histories with database pagination rather than load every stored request.

Coverage gap: route middleware was not fully audited. These files do not establish durable outgoing retries or parity with the hosted commercial product.

## F2. Hook0

Repository: [hook0/hook0](https://github.com/hook0/hook0), observed revision `6f57c41d00649ac4c68356945d33f1125c48d602`. The root [license](https://github.com/hook0/hook0/blob/6f57c41d00649ac4c68356945d33f1125c48d602/LICENSE.txt) and [API license](https://github.com/hook0/hook0/blob/6f57c41d00649ac4c68356945d33f1125c48d602/api/LICENSE.txt) contain SSPL v1. The output-worker license text was not separately read. Do not copy implementation code without license review.

Inspected code:

- [dns.rs](https://github.com/hook0/hook0/blob/6f57c41d00649ac4c68356945d33f1125c48d602/output-worker/src/dns.rs), lines 93-102, 242-245 and 358 onward: DNS deadlines, customer-safe error messages and forbidden address classification, including IPv4-carrying IPv6.
- [work.rs](https://github.com/hook0/hook0/blob/6f57c41d00649ac4c68356945d33f1125c48d602/output-worker/src/work.rs), lines 388-390: redirect refusal explicitly protects internal and metadata destinations.
- [pg.rs](https://github.com/hook0/hook0/blob/6f57c41d00649ac4c68356945d33f1125c48d602/output-worker/src/pg.rs), lines 101-102 and 296-325: locked work selection, persisted retry attempts and explicit exhaustion. Payload retrieval failures are delayed rather than retried in a hot loop.

Adopt dispatch-time address validation, DNS deadlines, redirect refusal and persisted retry scheduling. URL validation during configuration alone does not prevent DNS rebinding. OpenWarp's SQLite/PostgreSQL adapter needs portable conditional claims rather than a direct copy of PostgreSQL-specific locking SQL.

Coverage gap: the complete connection path and all retry branches were not audited. These observations do not establish whole-service SSRF safety.

## F3. WebhookHub

Repository: [Paramoshka/WebhookHub](https://github.com/Paramoshka/WebhookHub), observed revision `220f9f02aefa0b9e9c17c3fd167ee8f689ec693d`. Its [README](https://github.com/Paramoshka/WebhookHub/blob/220f9f02aefa0b9e9c17c3fd167ee8f689ec693d/README.md) identifies the requested Go, PostgreSQL and HTMX project and specifies AGPL v3 only or alternative commercial terms. The [license](https://github.com/Paramoshka/WebhookHub/blob/220f9f02aefa0b9e9c17c3fd167ee8f689ec693d/LICENSE) contains GNU AGPL v3. Do not transplant implementation code without license review.

Inspected code:

- [forwarder.go](https://github.com/Paramoshka/WebhookHub/blob/220f9f02aefa0b9e9c17c3fd167ee8f689ec693d/internal/forwarder/forwarder.go), lines 24-33, 92-166 and 199-254: redirect refusal, a fixed worker pool, attempt deadlines bounded by the lease, response capture capped at 1 MiB with truncation reporting, 2xx-only success and capped exponential backoff.
- [db_delivery.go](https://github.com/Paramoshka/WebhookHub/blob/220f9f02aefa0b9e9c17c3fd167ee8f689ec693d/internal/storage/db_delivery.go), lines 22-129: lease verification before an attempt, transactional attempt completion and delivery state, explicit dead-letter state and stale-worker fencing by lease version.
- [hmacsig.go](https://github.com/Paramoshka/WebhookHub/blob/220f9f02aefa0b9e9c17c3fd167ee8f689ec693d/internal/hmacsig/hmacsig.go), lines 32-64: timestamp tolerance, constant-time HMAC comparison and multiple signature candidates.

Adopt separate attempt history and delivery state, ownership fencing and explicit dead letters. Document at-least-once delivery and possible duplicates, as this project does. Timestamp tolerance does not prevent a valid request from being replayed within its accepted time window; OpenWarp needs persistent deduplication too.

Do not adopt raw response capture by default. A size limit does not make a credential-bearing response safe to store.

Coverage gap: incoming handler enforcement, all claim/replay/retention interactions and DNS/IP controls were not audited. Redirect refusal is only one part of outbound protection.

## F4. Svix

Repository: [svix/svix-webhooks](https://github.com/svix/svix-webhooks), observed revision `11fd588bc4754f19124ffa03a738fc4a1717ec46`. The inspected server [license](https://github.com/svix/svix-webhooks/blob/11fd588bc4754f19124ffa03a738fc4a1717ec46/server/LICENSE) is MIT.

Inspected code:

- [webhook_http_client.rs](https://github.com/svix/svix-webhooks/blob/11fd588bc4754f19124ffa03a738fc4a1717ec46/server/svix-server/src/core/webhook_http_client.rs), lines 104-147, 173-192 and 211-235: a dedicated resolver with network/name allowlists, TLS configuration, literal-IP checks, request timeouts and one immediate retry for selected fast transport failures.
- [security.rs](https://github.com/svix/svix-webhooks/blob/11fd588bc4754f19124ffa03a738fc4a1717ec46/server/svix-server/src/core/security.rs).
- [retry.rs](https://github.com/svix/svix-webhooks/blob/11fd588bc4754f19124ffa03a738fc4a1717ec46/server/svix-server/src/core/retry.rs), lines 23-61: bounded retry state and termination.
- [worker.rs](https://github.com/svix/svix-webhooks/blob/11fd588bc4754f19124ffa03a738fc4a1717ec46/server/svix-server/src/worker.rs), lines 493-622: `Retry-After` parsing, bounded receiver-requested delay and separate manual/scheduled retry handling.
- [queue/mod.rs](https://github.com/svix/svix-webhooks/blob/11fd588bc4754f19124ffa03a738fc4a1717ec46/server/svix-server/src/queue/mod.rs), lines 32-60: Redis, RabbitMQ and process-memory backend selection.

Adopt a dedicated webhook transport policy, explicit private-network exceptions and bounded receiver-controlled retry delays. Distinguish transport retries from scheduled attempts. Do not describe every queue backend as durable: the memory backend is not. A transport error also does not prove the receiver failed to process a request.

Coverage gap: only selected HTTP client, worker, retry and queue sections were inspected. The full resolver, persistence-to-queue handoff, signing protocol and logging policy were not audited.

## F5. webhookd

Repository: [ncarlier/webhookd](https://github.com/ncarlier/webhookd), observed revision `9e6625444060735abea0c2bc250baff5d52c7537`. Its [license](https://github.com/ncarlier/webhookd/blob/9e6625444060735abea0c2bc250baff5d52c7537/LICENSE) is MIT.

Inspected code:

- [authn.go](https://github.com/ncarlier/webhookd/blob/9e6625444060735abea0c2bc250baff5d52c7537/pkg/middleware/authn.go), lines 14-18: removes a supplied identity header before setting authenticated identity.
- [signature.go](https://github.com/ncarlier/webhookd/blob/9e6625444060735abea0c2bc250baff5d52c7537/pkg/middleware/signature.go), lines 11-22: verifies HTTP or Ed25519 signatures before dispatch.
- [dispatcher.go](https://github.com/ncarlier/webhookd/blob/9e6625444060735abea0c2bc250baff5d52c7537/pkg/worker/dispatcher.go), lines 7-31: a process-memory channel with capacity 100, followed by a goroutine per dequeued item waiting for a worker.
- [job.go](https://github.com/ncarlier/webhookd/blob/9e6625444060735abea0c2bc250baff5d52c7537/pkg/hook/job.go), lines 194 onward and 280-293: local script execution, output recording and process-group timeout handling.

Adopt verification before effects and removal of spoofable identity metadata. OpenWarp incoming hooks should invoke a fixed configured integration, never shell scripts or caller-selected commands. Do not acknowledge work that exists only in memory. A buffered channel alone does not bound waiting goroutines when its dispatcher drains into new goroutines.

Coverage gap: verifier internals, replay handling and the full acceptance path were not inspected. These files do not establish crash-safe persistence or durable retries.

## F6. OpenWarp at a633106

These findings describe the inspected baseline, not a subsequently implemented feature:

| Surface | Evidence and gap |
| --- | --- |
| Audit delivery | `crates/server/src/app.rs:182-224`: persisted log-stream rows coexist with fire-and-forget audit forwarding; native dispatch has immediate retries or unbounded thread creation. |
| Management and visibility | `app.rs:3656-3667,4261`: streams have create/list and delivery listing, without update/delete/replay routes in the inspected router. |
| Recovery | `app.rs:3705-3712`: stale pending deliveries are selected without an atomic delivery-level claim. |
| Storage | `crates/server/src/db.rs:384-385`: stream/delivery rows have no per-attempt history, ownership lease or retry schedule. |
| Egress | `app.rs:1700-1715,209,224`: literal-address checks do not resolve DNS; native audit clients lack explicit redirect refusal and dispatch-time validation. |
| Secret sync webhook | `crates/server/src/integrations.rs:590-605`: this adapter sends shared plaintext secret values, not workspace event metadata. It must remain a distinct action. |
| Incoming authorization | `app.rs:3493-3497`: ordinary IP middleware proceeds when token authentication fails. Dedicated hook credentials therefore need explicit workspace/IP enforcement. |
| MCP management | `app.rs:3519-3555,3986-4016`: REST scope middleware and MCP's tool-name mutation list are separate. A generic request tool must authorize the nested method with the real caller context. |
| Encryption boundaries | `app.rs:1246-1315`: incoming triggers must retain delegated-runner execution and exclusion of sealed values. |
| Client coverage | `crates/cli/src/main.rs:10-36` and the public methods in all four SDK clients lack webhook/integration setup and a generic management request method. |

## D1. Implementation requirements

- Persist accepted work before acknowledging it. Use immutable event bytes, stable event IDs, atomic claims and stale-owner fencing. State the actual boundary between a local secret write and event enqueue; persistence alone is not a transactional outbox.
- Sign exact bytes with message ID and timestamp. Use constant-time verification, bounded timestamp tolerance and durable replay detection. Rotate generated signing keys without exposing them in lists or delivery history.
- Validate destinations for every attempt, including all DNS results and IPv4-carrying IPv6. Refuse redirects and unintended proxy routing. Bound resolution, connection and total attempt time.
- Persist attempts, scheduled retries and terminal failure. Bound backoff, jitter, receiver-requested delay, concurrency and queue size. Document duplicate delivery and safe replay behavior.
- Expose event/delivery IDs, status, timestamps, duration, HTTP status, safe error category and next retry. Do not store raw incoming bodies, arbitrary headers or provider response bodies by default. Define retention and pagination.
- Bind incoming hooks to a fixed integration and recheck authority at acceptance and execution. Preserve tenant, role, environment, account status, credential scope, IP policy, delegated execution and E2E boundaries.
- CLI, SDK and hosted MCP management must use the same authorization rules as the HTTP API. An internal MCP request must preserve OAuth audience, scope and real peer context, and cannot accept arbitrary target URLs or spoofed identity headers.

These requirements are recommendations supported by the inspected source. Execution tests and an independent security review are still required for an OpenWarp implementation.
