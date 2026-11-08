# Batched secret change requests

A change request groups secret writes and deletions across environments in one workspace. Reviewers can inspect base values before approving a revision. Approval does not apply the changes; application is a separate action.

This API is separate from the older per-environment proposal API, whose approval applies immediately. The browser console's existing proposal controls do not manage this batched API.

## Create a request

Send `POST /api/orgs/ORG_ID/change-requests` with a title and environment operations:

```json
{
  "title": "Update application configuration",
  "changes": [
    {
      "env_id": "ENV_ID",
      "secrets": [{"key": "DATABASE_URL", "value": "dummy-value", "path": "/"}],
      "deletes": [{"key": "OBSOLETE", "path": "/"}]
    }
  ]
}
```

Use a protected API client for real values rather than command-line arguments or shared request logs. The caller needs `proposals:write` and access to every environment. The title is 1-200 bytes, the batch accepts 1-20 distinct environments, and there must be 1-500 operations in total. A logical key/path pair cannot appear twice. Key normalization and secret-type validation follow ordinary secret writes.

Only managed SSE environments are accepted. E2E and delegated environments return 409 because the server cannot inspect their plaintext for this review workflow. Do not upload client-encrypted secrets through this path.

The server captures the affected rows and desired values in an encrypted per-environment payload. Associated data binds the payload to its request, environment and revision. Snapshots contain base secrets, not personal overrides.

## Review and edit

`GET /api/orgs/ORG_ID/change-requests` lists request metadata visible to the caller. `GET /api/change-requests/REQUEST_ID` returns the review, requiring `secrets:read` and access to all affected environments. The response includes `changes`, with each environment's `items` containing `key`, `path`, `before` and `after`. Values on both sides are redacted when either side is sealed.

The author can replace a pending or approved request with `PUT /api/change-requests/REQUEST_ID`. Supply the current `revision` together with the replacement title and full changes array. A successful edit increments the revision, clears approval and returns the request to pending. It also takes fresh baseline snapshots. Concurrent edits using an old revision return 409.

## Approve, apply or reject

Send a JSON body containing the expected `revision` to these routes:

| Route beneath `/api/change-requests/REQUEST_ID/` | Effect |
| --- | --- |
| `approve` | An admin approves the pending revision without changing secrets |
| `apply` | An admin applies the approved revision |
| `reject` | An admin rejects a pending or approved request |

The author cannot approve or apply their own request. Each action checks current access to every environment. Application also checks write/delete permissions for the requested operations.

Application also honors each environment's `max_versions` retention policy. The limit is snapshotted once per environment and guarded in the same transaction, so an apply conflicts if policy changes after preparation instead of pruning under a stale limit.

Application verifies that every captured target is unchanged, including deletions, recreations and previously absent logical keys. Any conflict returns 409 and leaves the batch unapplied. Rebase by editing, review the new diff, then approve that revision. A request that has already been applied cannot be applied again.

Local changes and version history commit together in a checked database transaction. Native PostgreSQL briefly locks the secrets table against other writers during guarded application; this favors atomicity over concurrent write throughput. Native SQLite uses an immediate transaction. Provider sync runs after commit and reports errors per environment in `sync_errors`. A provider failure does not undo the committed local batch.

## Deployment limits

The Workers Durable Object backend uses a synchronous checked transaction. Local runtime tests exercise stale-batch rollback and successful rebase. The API does not provide client-side encrypted review, multi-workspace batches, multiple required reviewers or scheduled application. Existing proposals are a distinct workflow and do not acquire these guarantees automatically.

[Security model](SECURITY.md) | [Console](CONSOLE.md)
