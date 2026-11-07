# Assistant and security insights

OpenWarp has two separate AI-related workflows: a workspace assistant and deterministic security insights. The assistant uses a model endpoint configured by your instance operator and workspace administrator. Security findings do not require a model or a provider key.

## Configure an endpoint

The operator sets `OPENWARP_AI_ENDPOINTS` to a JSON array of exact chat-completion URLs. An empty or missing list disables model requests. Workspace administrators cannot supply an endpoint outside that list. Paths and query strings are part of the match.

The endpoint accepts a non-streaming OpenAI chat-completions request with `model`, `messages`, and `max_tokens`. Responses contain `choices[0].message.content`. The assistant requests JSON containing an answer, supplied source IDs, and optional typed suggestions. Plain-text responses remain readable but have no validated citations or setup suggestions. This is a wire contract, not a claim that every model server supports the same behaviour. Model tool calling is not required.

An explicitly allowed private-network endpoint can host a local model. Allowing it does not require `OPENWARP_ALLOW_PRIVATE_EGRESS=1`. The allowlist is an operator trust decision about the destination, including its DNS and network routing. Restrict outbound traffic at the network layer too. Native inference disables redirects and ambient HTTP proxies.

In the console, open Assistant settings for the workspace. Choose an allowed endpoint and model, then supply a provider key if the endpoint requires one. The key is encrypted at rest and write-only. A blank key field preserves the saved key when the endpoint is unchanged. Changing the endpoint clears the previous key unless you supply a replacement; the explicit clear control also removes it. Provider keys are authentication headers, not model context.

AI settings default to off. Administrators separately allow metadata disclosure, confirmed setup actions, and local value matching. Daily request and reservation limits restrict consumption. Reservation units use request bytes plus the output allowance; they are deliberately conservative and are not a provider billing report or an exact tokenizer count.

Inference is available on the native server. The Workers build refuses inference rather than dropping redirect, response-size, or deadline restrictions. Local discovery, plans, and security insights do not depend on inference.

## What the model can receive

With metadata disclosure enabled, the assistant can receive the question and a bounded selection of authorised managed-environment metadata: secret names and paths, application/environment names, record identifiers, and task-specific operational fields. Search and citations use the caller's current workspace and environment access.

OpenWarp does not send stored secret values, comments, provider configuration, recovery keys, or arbitrary audit/provider-error text to the model. It does not create embeddings of secret values. Names and paths can still reveal internal architecture, so an external model is an additional recipient of sensitive metadata.

The question itself is sent to the endpoint. Do not paste credentials into the chat box. Import assistance uses a separate input that OpenWarp parses locally; the model receives names rather than imported values. This input accepts single-line dotenv assignments and rejects multiline, unbalanced quoted, or unsupported syntax before inference. The disclosure policy cannot make a credential typed directly into an ordinary question safe to send.

E2E and delegated secret metadata is not decrypted on the server for AI. Those environments do not gain a server-side plaintext index. Client-side E2E inspection and runner-based inference are not provided.

## Find a secret

Local metadata search finds permitted records without making a model request. Each result identifies its application, environment, and path. Opening a record uses the normal console; the assistant does not print its value.

An administrator can separately enable local value matching. It inspects a bounded set of permitted non-sealed managed-environment values inside OpenWarp and returns record references. Values with ciphertext larger than 64 KiB are skipped, with truncation reported. It does not send those values to the model. A match can itself reveal information about a credential, so this operation needs the same read access as the underlying value. It is unavailable for E2E and delegated data.

Model-assisted discovery helps interpret a question and select among the supplied records. Responses show validated sources. A source link proves which record the assistant used, not that every inference in its prose is correct. Missing sources or truncated context should be treated as incomplete coverage.

## Prepare setup changes

The assistant can suggest folders and integration drafts. Suggestions do not execute automatically. A preview records the exact operations, their targets, and an expiry. Confirming the preview executes that stored plan; changing the requested operations requires a new preview.

Execution checks current membership, permissions, environment policy, and workspace AI settings again. A pending plan does not preserve access after revocation. Plans are bound to their author and workspace and can be claimed only once. Results report completed and failed operations separately. A partially completed plan is not an atomic transaction; inspect its results before preparing another.

A folder is a persisted empty path, not a secret with a placeholder value. Integration drafts are separate from active integrations. Complete a draft through the normal integration form and enter credentials there. Creating a draft does not test credentials, contact a provider, or sync secrets. Testing and syncing remain separate manual actions with their own external effects.

The assistant cannot execute arbitrary SQL, shell commands, or HTTP requests. It cannot autonomously delete data, grant access, issue tokens, or rotate credentials. Retrieved names and model responses are untrusted data; application permission and confirmation checks apply outside the model.

## Investigate and organise

The assistant offers task-specific guidance:

- Integration troubleshooting uses recorded manual-sync status and provider kind without exposing configuration credentials or raw provider errors. Automatic deploy and rotation syncs are not covered by that status; before the first observed manual sync it is unknown.
- Environment drift compares authorised metadata. It does not imply that equal names have equal values.
- Incident investigation and access review require workspace administration permission and use restricted operational projections.
- Rotation guidance prepares a checklist around existing schedules and integrations. It does not run a rotation.
- Import organisation proposes names and paths before an import. It does not submit imported values to inference.

Guidance depends on the supplied context. The assistant should not be treated as proof that a provider accepted a change or that an account has never used a credential.

## Security findings

Security insights use rules and available history. Findings include the triggering rule, rationale, and evidence references. They remain available when inference is disabled or unavailable. An optional explanation adds model-written interpretation; it does not change the evidence or execute a response.

The initial rules check read/export bursts in fixed ten-minute UTC windows, read volume above an established baseline, new actor/environment combinations after a baseline, integration changes followed by an observed sync, token creation followed by an export, resources expiring within seven days, and overdue rotation schedules. These are investigation signals, not proof of compromise. Authentication anomalies and privilege-escalation correlation are not inferred from missing telemetry.

The baseline uses at most 2,000 structured events from the preceding 14 days and requires at least seven observed days and 50 older events. Activity and background finding history have a 30-day retention window. Bounded context and retention can omit relevant events; inspect the coverage fields before drawing conclusions.

The activity stream stores structured counts and resource references rather than secret values. Token attribution uses a keyed pseudonym rather than a raw credential. Existing audit history is best-effort and does not establish complete historical read, export, authentication, or token coverage. The insights view reports history limits and insufficient baselines. An empty findings list is not evidence that all activity was safe.

Administrators can acknowledge a finding or record an exception with an expiry and a maintenance note. Notes do not enter model context. Exceptions should cover a specific investigation or maintenance window rather than permanently hiding unusual activity.

Background monitoring, when enabled, runs bounded deterministic checks. It does not make background model requests or revoke credentials automatically. Notification delivery and external incident-response automation are not provided by the assistant.

## Conversation and operational records

The assistant does not persist a chat transcript. Plans, drafts, settings, findings state, usage reservations, and structured activity are persistent operational data. Treat database backups as sensitive even when no secret values are present in these records.

Operational logs must not contain prompt bodies, provider keys, or secret values. Provider-side storage and retention are controlled by the endpoint operator. Removing a local record cannot retract information already sent to that endpoint.

## API boundaries

Assistant and insights endpoints initially accept account sessions, including the console's session cookie. Service tokens, machine tokens, and OAuth access tokens are refused, even when they represent an administrator. This keeps the first release from turning a narrow automation credential into a workspace-wide AI credential.

| Route under `/api/orgs/{org_id}/ai` | Purpose |
| --- | --- |
| `GET`/`PUT /settings` | Read safe policy fields; administrators configure AI |
| `GET /context` | List permitted managed environments and safe integration metadata |
| `GET /search?q=...` | Local metadata discovery |
| `POST /local-search` | Explicit local value matching |
| `POST /chat` | Model-assisted question or guidance |
| `POST /plans` | Create an immutable preview |
| `POST /plans/{plan_id}/execute` | Confirm and claim the stored plan |
| `GET /drafts` | List authorised integration drafts |
| `DELETE /drafts/{draft_id}` | Remove a draft after completion or cancellation |
| `GET /findings` | Administrator-only deterministic findings |
| `PUT /findings/{finding_id}` | Acknowledge a finding or manage an expiring exception |

`GET /api/envs/{env_id}/folders` lists persisted folders under normal environment read permissions.

[Configuration](CONFIGURATION.md) · [Security model](SECURITY.md) · [Console](CONSOLE.md) · [Documentation index](README.md)
