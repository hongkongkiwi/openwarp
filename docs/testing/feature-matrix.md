# Feature coverage matrix

Ledger bound to commit 8425e29, branch `feat/comprehensive-clients` (2026-11-09), read together with the working tree as of that date. How to run things: [../TESTING.md](../TESTING.md). Step-level journeys: [scenarios.md](scenarios.md). Sequencing and rollout: [../plans/2026-11-09-comprehensive-testing.md](../plans/2026-11-09-comprehensive-testing.md).

## How to read this ledger

- Status describes the suite inventory, not a run. Nothing here was executed during planning. `covered` means suites exist for the area; case-level verification of what those suites actually assert happens in the baseline pass (rollout plan, phase A2). `partial` means named gaps remain. `gap` means no dedicated suite was found in the inventory. `proposed` requires new tooling.
- Every applicable feature needs success, malformed-input, denied-access and persistence/state assertions. A sensitive rejection must leave storage and remote state unchanged and must not reveal secret material.
- Features known from project history but absent from this revision are listed under "Out of this revision" at the end, with evidence. They enter this ledger only when merged into the tested revision.

## Security dimensions

Applied across every row: map authentication class, required scope, resource boundary, relevant policy and documented error behavior for each route. Assert the denied response and the absence of side effects. Preserve intentional 404 versus 403 semantics.

- Actors: anonymous, owner, admin, ordinary member, read-only member, custom privileged and non-privileged roles, removed or locked member.
- Credentials: cookie session, personal/service token, environment-scoped token, OAuth token, workload identity, runner credential, wrapping token.
- Resources: own workspace, sibling workspace, inaccessible app or environment, deleted object, reused-looking identifier.
- Policy: restricted or approval-required environment, IP rules, E2E and delegated mode, MFA/step-up, workspace and app lockdown.
- Timing: before, at and after expiry; concurrent requests; revocation during a request or job; restart between steps.

Enumerate these boundaries fully. Pairwise combinations are acceptable only for lower-risk presentation and configuration variants.

## Identity and access

| ID / feature | Source and existing suites | Unit and contract cases | End-to-end cases | Status |
| --- | --- | --- | --- | --- |
| F01 Accounts and sessions | `main.rs`, `mailer.rs`, `auth-v2.js`; `accounts.rs`, `auth_methods.rs`, `client_auth.rs`, `security.rs`, `account_merge.rs`, `cookie_scope_merge.rs` | Registration validation, email verification, client-derived auth protocol, session expiry and revocation, cookie flags and scoping, CSRF/origin rules, enumeration-resistant failures | Register through captured email, verify, sign in and out, reset and recover, revoke sessions, reject stale credentials, account deletion with workspace-ownership safeguards | covered |
| F02 Federation and directories | `main.rs`, `social_extra.rs`, `ldap.rs`, `mfa.rs`; `accounts.rs` (local OIDC mock), `social_merge.rs`, `social_binding_merge.rs`, `auth_methods.rs`, `ldap.rs` | Per-provider config mapping, OIDC issuer/audience/nonce/azp/JWKS/PKCE/state, SAML assertions and replay, LDAP TLS/search-bind/group mapping, account linking with login-time proof for existing emails | Round trips against local fakes, MFA after federation, wrong-browser and replayed callback rejection, provider outage fail-closed, disabled-provider behavior | covered |
| F03 MFA, passkeys, step-up | `mfa.rs`, `mfa_wasm.rs`, `main.rs`; `auth_methods.rs`, `security.rs` (confirm step-up cases in A2) | TOTP windows and replay, recovery-code single use, WebAuthn challenge/origin/RP binding, grant action and session binding, expiry | Enroll, authenticate, recover, remove under policy; virtual authenticator journey; privileged-action challenge; replay rejection | covered |
| F04 Workspaces and membership | `main.rs`, `app.rs`; `authorization.rs`, `account_merge.rs`, `product_scope_regressions.rs` | Invitation lifecycle and expiry, role and ownership rules, leave and delete guards, account versus workspace separation | Two users, two workspaces: invite, accept, reject, switch, rename, transfer ownership, leave, delete; member locks; consent invitations | covered |
| F05 Authorisation and access | `main.rs:171-223` (`check_scope`, `role_perms`, `require_org`, `require_env`); `authorization.rs`, `security.rs`, `product_scope_regressions.rs`, `product_security_remaining.rs` | Permission tables for each role, default-deny custom roles, team grants, environment policy, IP allowlists, member locks | Role and credential matrix across sensitive routes; cross-tenant identifiers; escalation denied; revocation takes effect immediately | covered |
| F06 Tokens, OAuth, workload identity | `main.rs`, `workload.rs`; `client_auth.rs`, `security.rs` (workload exchange cases: locate in A2) | Scope/audience/environment narrowing, TTL, rotation, revocation, JWT trust matching, OAuth consent and PKCE semantics | Issue, use and revoke least-privilege credentials; sibling environment denied; workload JWT exchange against a local issuer; unknown trust fails closed | covered |

## Secrets and encryption

| ID / feature | Source and existing suites | Unit and contract cases | End-to-end cases | Status |
| --- | --- | --- | --- | --- |
| F07 Apps and environments | `app.rs`, `main.rs`; `product_features.rs`, `semantics.rs` | Name and path rules, duplicate handling, environment policy and mode restrictions | Create, edit, clone, compare, delete; policy and isolation preserved; dependent-resource deletion follows contract | covered |
| F08 Secrets and metadata | `app.rs`, `db.rs`, `main.rs`; `semantics.rs`, `encryption.rs`, `product_features.rs` | Secret, config, sealed and SSH-key types; `(environment, path, key)` normalisation; folders, tags, comments, filters; size and encoding limits | CRUD across folders and types; sealed values never surface through read, export or history paths; search and pagination exclude inaccessible records | covered |
| F09 Versions and recovery | `app.rs`, `db.rs`; `semantics.rs`, `product_features.rs` | Version sequencing, conditional-update CAS, soft delete, undelete, destroy, retention, restore, point-in-time recovery | Competing updates resolve as documented; stale writes rejected; restore a selected version; destroyed values unavailable; retention survives restart | covered |
| F10 References, overrides, files | `app.rs`, `main.rs`; `override_reader_merge.rs`, `product_features.rs` | Reference expansion, cycles and missing targets, override precedence and isolation, import/export escaping, binary and path limits | Import/export round trips across formats; references respect target access; personal overrides affect only their reader; file transfer preserves bytes | covered |
| F11 Reuse detection | `app.rs`, `db.rs`, `integrations.rs`, `ui.rs`; reuse cases in `product_features.rs` / `product_scope_regressions.rs` (confirm in A2) | Workspace-salted fingerprints over `secret` values only, exclusions (sealed, config, SSH, E2E), toggles, backfill, rotation | Warning surfaced without disclosure; no cross-workspace equality oracle; inaccessible environments excluded | covered |
| F12 Managed encryption and KMS | `kms.rs`, `kms_wasm.rs`, `crates/crypto/src/lib.rs`; `encryption.rs`, `openwarp-crypto` unit tests | AEAD tamper and AAD mismatch, malformed envelopes, key lengths, wrap/unwrap, KMS error paths and versioning, master-key requirements | Managed round trip; restart with wrong master key; rotation; KMS outage and wrong-key failures; storage and logs contain no plaintext | covered |
| F13 E2E encryption and recovery | `e2e.js`, `kms.rs`, `db.rs`; `encryption.rs`, `e2e-libsodium.test.cjs` | Browser crypto vectors, `ow2:` record-bound metadata, HMAC blind index, wrapped-key grants, tamper rejection, recovery parsing | Client-keyed creation, write and read in the browser, reload and unlock, recovery kit, multi-user grant, revoke and rekey; captured requests and stored rows are ciphertext; compatibility creation is never described as server-blind | covered |

## Automation and sharing

| ID / feature | Source and existing suites | Unit and contract cases | End-to-end cases | Status |
| --- | --- | --- | --- | --- |
| F14 Delegated runners | `worker.rs`, `workload.rs`; `delegated.rs`, `product_portability.rs` | Runner binding, job authorisation, claim, ack, expiry, replay, allowed job types | Outbound runner executes an authorised job against a disposable target; revocation mid-flow; retries do not duplicate effects; no server-plaintext fallback for E2E | covered |
| F15 Change requests | `change_requests.rs`, `main.rs`; `product_features.rs`, `product_scope_regressions.rs` | Proposal state transitions, reviewer eligibility, self-approval policy, stale proposals, atomic apply | Propose, review, reject, apply; direct-write bypass denied in approval-required environments; competing apply and changed base revision handled | covered |
| F16 Provider sync and import | `integrations.rs`, `main.rs`; `sync_config_merge.rs`, `sync_collisions_merge.rs`, `sync_review_merge.rs` | Per-adapter requests, auth, pagination; naming, case, templates, paths, filters, tags; capability table; managed-name state; dry-run; mirror deletion | Configure, test, sync, import against local mocks; deployment-triggered sync; remote failure reported even when the local deploy succeeded; mirror deletes only eligible managed resources | covered, per-adapter contract cases tracked separately (see "Provider rows" below) |
| F17 Rotation and dynamic leases | `inference_leases.rs`, `worker.rs`, `pglease.rs`, `mysqllease.rs`; `product_features.rs`, `product_portability.rs`, `mysql_backend.rs` | Reservation before provider call, pending and ambiguous failures, reconciliation, expiry, renewal, revocation, backend grant validation | Credential demonstrably works, then fails after revoke or expiry; duplicate dispatch; remote timeout; restart; workspace deletion refused while unresolved leases exist | covered |
| F18 Lockbox and wrapping tokens | `main.rs`, `app.rs`; `product_features.rs`, `product_security_remaining.rs` | Expiry bounds, attempt and password policy where exposed, token scope, route confinement, sealed-value exclusion | Two concurrent readers of a single-use value produce exactly one winner; replay and expiry fail; lookup does not consume; wrap tokens cannot authenticate unrelated routes | covered |
| F19 Transit | `transit.rs`, `main.rs`; `product_features.rs`, `product_security_remaining.rs` | Key versioning, rotation, encrypt/decrypt/rewrap permission separation, ciphertext-only rewrap, malformed ciphertext | Client round trip and rotation; wrong workspace, key or version rejected; compatibility namespaces tested separately from native transit | covered |
| F20 PKI and SSH certificates | `pki.rs`, `ssh_ca.rs`, `ssh_keys.rs`; `ssh_scope_merge.rs`, `product_security_remaining.rs`, module tests in `ssh_ca.rs` | CSR and principal validation, wildcard restrictions, signing validity, CA key wrapping, registered-host matching, KRL output | Issue and verify certificates with independent protocol tools; step-up for root-equivalent principals; machine identities denied privileged principals; revocation enforced once hosts refresh revocation data | covered |

## Platform

| ID / feature | Source and existing suites | Unit and contract cases | End-to-end cases | Status |
| --- | --- | --- | --- | --- |
| F21 Audit, live events, notifications | `log.rs`, `worker.rs`, `mailer.rs`; `product_features.rs`, `hardening_merge.rs` | Hash-chain sequence and linkage, tamper detection and first-broken-link reporting, redaction, permission filtering, replay cursors, mail rendering, bounded retries | Mutations produce correct redacted entries; deliberate tampering detected; live reconnect with `?since` does not leak other tenants; delivery failure does not corrupt the primary operation | covered |
| F22 Emergency lockdown | `main.rs`, `app.rs`; `emergency.rs`, `emergency_merge.rs`, `product_lockdown.rs` | Workspace and app lock composition, cookie-only owner callers, credential invalidation, queued-work revalidation | Lock with clients and runners active; protected reads, writes, exports, history, E2E access and sync dispatch fail; unlocking one layer does not clear the other or revive revoked credentials | covered |
| F23 Console behavior | `ui.rs`, `e2e.js`, `i18n.js`; `ui.test.cjs`, `product-ui.test.cjs`, `product-ui-races.test.cjs` | Render helpers, escaping, stale-response guards, theme and language state | Every view, dialog and destructive confirmation; navigation during slow requests; keyboard and focus; error, loading and empty states; desktop and mobile layouts; translations preserve user data | covered (source checks) + proposed (browser matrix) |
| F24 CLI | `crates/cli/src/main.rs`; no test file found in `crates/cli` | Parser, config handling, output formats and escaping, exit codes, credential precedence, redaction | Login, list, read, write, import, export, sync, inject and every other parser-discovered command against a real server; injected child receives the intended environment; errors do not print secrets | gap (verify during A2) |
| F25 SDKs and OpenAPI | `sdk/rust`, `sdk/go`, `sdks/typescript`, `sdks/python`, `openapi.json`, `scripts/check-openapi.py`; `sdks/typescript/sdk.test.ts`, `sdks/python/test_*.py`, `sdk/rust` tests, `sdk/go/client_test.go` | Serialisation, authentication, errors, pagination, timeouts and documented retries per client | Shared real-server scenario corpus; every supported operation exercised; unsupported operations explicit; `sdk/go` tests exist but no CI step invokes them (A2 item) | partial |
| F26 Terraform, Action, ESO | `terraform-provider/`, `terraform-provider-openwarp/`, `action/` (no test files present), `crates/eso/src/main.rs` (10 inline tests) | Provider schema, sensitive state, validation; action input handling and output masking; ESO request/response and not-found mapping | Terraform CRUD, import, destroy and an idempotent second plan; action entrypoint in a fixture runner environment; ESO reconcile and delete against an ephemeral Kubernetes cluster; no real deployment | partial |
| F27 Storage and migrations | `db.rs` (SQLite/PostgreSQL/MySQL/MariaDB translation, numbered `MIGRATIONS`); `postgres_backend.rs`, `mysql_backend.rs`, `product_portability.rs` | Placeholder translation, DDL rewrite rules (TEXT keys, defaults, index guards, collation), transaction semantics, migration ledger ordering, backend reserved words | Fresh install, upgrade along supported histories, no-op on current, interrupted migration retry, concurrent startup; security, CAS, approval, unwrap and lease parity across backends | partial (no dedicated historical-upgrade suite found) |
| F28 Packaging and operations | `worker.rs`, `envcfg.rs`, `clock.rs`, `bin/`; `product_portability.rs`, `hardening_merge.rs`, `scripts/tests/portable-runtime/worker-deployment.test.cjs`, worker smoke scripts, CI docker job | Config validation, production `OPENWARP_MASTER_KEY` requirements, egress guards, lease ownership and single-replica dispatch, clock boundaries | Container product journey; workerd journeys and persistence; proxy HTTPS and cookie behavior; graceful shutdown; backup and restore rehearsal | partial (replica and compose-topology cases not covered by a suite) |

## Provider rows

One row per adapter is maintained in the sync/lease contract work: every adapter discovered in `integrations.rs` and every lease, identity and mail provider gets contract assertions on its actual protocol, capability set, config redaction, error parsing and deletion behavior, using protocol-family mocks. Explicitly test unsupported capabilities rather than assuming all adapters support import, mirror, dry-run or connection test. Live validation is tier 3 in [../TESTING.md](../TESTING.md) and is never implied by a passing mock.

## Out of this revision

Verified at 8425e29 by source search (`rg -i`) and `git merge-base --is-ancestor`. These exist on other branches per project history and are not shipped in this revision; they join this ledger when merged.

| Feature | Evidence |
| --- | --- |
| Enterprise licensing | No licensing code in `crates/server/src`; merge commit 4385d2c is not an ancestor |
| AI assistant and insights | No source hits; 00b1204 is not an ancestor |
| Device certificates and IoT enrollment | No enrollment or attestation code in `pki.rs`; d39138e is not an ancestor |
| Secret health (breach checks) | 449736b is not an ancestor |
| Login jurisdiction and region picker | 255dfc6 is not an ancestor |
| OpenBao transit-compat namespace | b3eea91 is not an ancestor |
| Agent credential broker | No source hits; feature branch unmerged per project history |
| Wallet storage and signing | No source hits; feature branch unmerged per project history |

Present and confirmed at this revision, despite similar-sounding history: password reuse detection (db7dd27), LDAP directory sign-in (9395c87), SSH certificate authority (9200fdb), SAML and passkeys/WebAuthn (source hits in `app.rs`, `mfa.rs`, `db.rs`), SCIM (source hit in `app.rs`), lockbox (source hits in `app.rs`, `db.rs`, `ui.rs`).
