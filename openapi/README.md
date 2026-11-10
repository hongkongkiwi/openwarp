# OpenAPI source fragments

`openapi.json` at the repository root is generated. Edit the fragments here and
run:

```bash
python3 scripts/openapi-build.py
```

The build merges `base.json`, every file in `paths/` and every file in
`schemas/`, then writes the contract with sorted keys. Two fragments that define
the same path or schema differently fail the build instead of silently winning
by file order.

| File | Contents |
|---|---|
| `base.json` | `openapi`, `info`, `servers` |
| `paths/*.json` | one file per resource family, each a path map |
| `schemas/*.json` | one file per resource family, each a schema map |

`scripts/check-openapi.py` runs the build with `--check` and then validates the
result against the routes registered in `crates/server/src/app.rs`. CI fails on
a stale contract, a documented route the server does not serve, an unresolved
schema reference, or an undeclared path parameter.

Rules for edits:

- Read the handler before describing an operation. A summary that guesses is
  worse than a missing path.
- Reuse the shared `Error`, `Ok`, `Deleted` and `Id` schemas where they match.
- Every operation needs `summary`, `tags`, path parameters, `responses` and
  `security`. Add `requestBody` only when the handler reads a body.
- Browser-only and protocol surfaces (console assets, OAuth authorization, the
  MCP transport itself, SCIM, SAML/OIDC callbacks) stay out of the contract.
  `scripts/check-openapi.py --strict` lists them as the allowed remainder.

## Deliberately outside the machine contract (as of this lane)

Instance and account-administration surfaces that predate the contract and are
console-only today: `/api/auth/invite`, `/api/capabilities`,
`/api/instance/{edition,features,workspaces}`, `/api/me/sessions`,
`/api/me/secret-health*` (incl. Enzoic and LeakCheck helpers),
`/api/integrations/{iid}/history`, `/api/orgs/{oid}/features`,
`/api/orgs/{oid}/identities/{iid}/workload`, `/api/envs/{eid}/path-policy/*`,
and the invitation acceptance pair. Documenting them is a follow-up pass; the
strict mode of `check-openapi.py` fails until then, so CI runs plain mode.
