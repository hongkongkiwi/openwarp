# Acceptance scenarios

Executable journeys behind the coverage ledger in [feature-matrix.md](feature-matrix.md). Each scenario lists prerequisites, actions, expected outcomes and cleanup. Prerequisites may use the API; the behavior under test must use the interface named in the scenario (API, CLI or browser).

Common fixture rules are in [../TESTING.md](../TESTING.md): disposable databases, local fakes, teardown on every exit path, no secrets in artifacts. Scenarios marked "browser" need the rebuilt server (`cargo build` then restart; a stale binary hides the edit) and, once the Playwright tooling exists, run from `tests/e2e/`.

## Identity and access

**S01 Account lifecycle** (F01, API). Mailbox fake captures mail. Register, receive verification mail, verify, sign in, sign out, request reset, reset from the mailed link, sign in with the new password. Expected: unverified sign-in refused, old password refused after reset, enumeration-resistant errors for unknown accounts. Cleanup: suite database discarded.

**S02 OIDC federation** (F02, API). Local OIDC mock from `accounts.rs`. Sign in through discovery, JWKS and token exchange; assert state-cookie binding. Repeat with a replayed state, a state from a different browser session, a provider error callback, and a tampered id_token. Expected: exactly one success; every hostile variant fails closed with no session created.

**S03 MFA and step-up** (F03, API plus browser). Enrol TOTP, sign in with a current code, replay the same code, use a recovery code twice. Expected: replay and second recovery use refused. For a privileged action on a browser session, expect the step-up challenge; grant expires and re-prompts.

**S04 Workspace administration** (F04, API). Two accounts. Owner invites a member; member accepts. Switch workspaces, rename, transfer ownership, member leaves, workspace deleted last. Expected: leave refused while the member owns resources per contract; deleted workspace returns the documented error for both callers; member locks block sign-in to that workspace only.

**S05 Authorisation matrix** (F05, API). Generate the actor and credential sets from the ledger's security dimensions. For each sensitive route: expected result for allowed caller, denied response and zero side effects for every other combination, including cross-workspace identifiers and revoked or locked members.

**S06 Tokens and workload identity** (F06, API). Issue a token scoped to one environment; prove access inside, denial in a sibling environment and workspace; revoke; prove immediate denial. Exchange a workload JWT from a local issuer; repeat with an unknown trust anchor and expect fail-closed.

## Secrets and encryption

**S07 Secret lifecycle** (F07-F09, API). Create app and environments, write secrets across types and folders, update concurrently with a stale CAS token, restore an older version, soft delete, undelete, destroy. Expected: version sequence intact, stale write rejected, destroyed value unavailable everywhere including history and export.

**S08 Import, export, references, overrides** (F10, API and CLI). Import dotenv and JSON fixtures, export, re-import into a fresh environment. Create a reference and a personal override; read as the override's reader and as another member. Expected: round trip preserves values and escaping; references resolve only with target access; overrides are invisible to other readers.

**S09 Reuse detection** (F11, API). Plant a duplicate `secret` value within one workspace and the same value in another workspace, plus a sealed and an E2E duplicate. Expected: warning appears only for the in-workspace secret duplicate, without revealing values; exclusions hold.

**S10 E2E environment** (F13, browser). Client-keyed creation; recovery kit download; write and read a secret in-page; reload and unlock with the kit; grant a second member; revoke and rekey. Expected: captured requests and database rows contain ciphertext only; revoked member cannot read after rekey; the compatibility creation path is labelled as server-generated in the UI.

**S11 Managed crypto and KMS** (F12, API). Round trip a managed secret; restart the server with a wrong master key and expect startup failure; rotate and confirm old reads still resolve or fail as documented; point KMS at an unavailable endpoint and expect clear errors without plaintext leakage.

## Automation and sharing

**S12 Provider sync** (F16, API with mocks). Configure a destination against a capture mock; run test, sync and import; trigger a deploy; make the mock fail mid-batch. Expected: requests match the adapter contract; remote failure is reported per item even though the local deploy succeeded; mirror deletion removes only managed eligible entries; sealed values and overrides are never sent.

**S13 Dynamic lease** (F17, API against a disposable MySQL or PostgreSQL). Issue a lease, connect with the issued credential, revoke it, reconnect and fail. Repeat with a provider timeout to force the ambiguous path, then reconcile. Expected: one credential issued per reservation, revocation effective, workspace deletion refused while a lease is unresolved.

**S14 Lockbox race** (F18, API). Create a single-use wrap, then issue two concurrent redemptions. Expected: exactly one 200, one failure, one consumed token, and the redemption route is the only route the token authenticates.

**S15 Transit and PKI** (F19, F20, API and protocol tools). Transit: encrypt, rewrap to a new version, decrypt; wrong workspace and stale version refused. PKI: issue a user certificate, verify it with an independent SSH or OpenSSL tool, revoke it, confirm rejection after revocation data refresh; request a root-equivalent principal without step-up and expect refusal.

## Platform

**S16 Audit and lockdown** (F21, F22, API). Perform mutations, verify the chain, flip a byte in the store and confirm tamper detection reports the first broken link. Lock the workspace as owner while a token client is mid-read; expect queued and new protected operations denied; unlock and confirm the other lock layer and revoked credentials behave per contract.

**S17 Console journeys** (F23, browser). Walk every view and dialog in the matrix: apps, environments, secret editing with drafts, access, integrations, audit, settings. Include destructive confirmations, navigation away during a slow request, keyboard-only operation, error and empty states, mobile width, theme and language switching with user data intact.

**S18 CLI lifecycle** (F24, CLI). Against a real server: login, set defaults, read, write, import, export, sync, inject a child process. Expected: env contains exactly the intended keys, exit codes match the contract, errors never echo secret values.

**S19 SDK corpus** (F25, SDKs). One shared scenario (auth, CRUD, errors, pagination, export) executed by the TypeScript, Python, Rust and Go SDKs against the same server build. Expected: identical observable behavior within each client's documented contract.

**S20 Terraform, Action, ESO** (F26). Terraform: plan, apply, re-plan (no diff), import, destroy. Action: run `index.js` in a fixture runner with masked outputs. ESO: reconcile a secret into an ephemeral cluster, then delete the source and confirm `deletionPolicy` behavior.

**S21 Backend parity and deployment** (F27, F28). Run S01, S05, S07, S14 and the lease scenario against PostgreSQL and MariaDB in addition to SQLite, plus migration upgrade, retry-after-interruption and restart cases. Then the container journey and the workerd smoke, including persistence across worker restarts.

## Recording results

A scenario is complete only with executed evidence: command or suite name, revision, counts and failures. Record skips as skips. Any scenario that cannot run for lack of a fixture or service is blocked, not passing.
