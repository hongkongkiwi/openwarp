# OpenWarp Go SDK

Requires Go 1.21+ and only the standard library. Module: `github.com/hongkongkiwi/openwarp/sdk/go`.

```go
package main

import (
    "context"
    "log"
    "os"

    openwarp "github.com/hongkongkiwi/openwarp/sdk/go"
)

func main() {
    client := &openwarp.Client{
        BaseURL: os.Getenv("OPENWARP_URL"),
        Token:   os.Getenv("OPENWARP_TOKEN"),
    }
    ctx := context.Background()
    _, err := client.SetSecret(ctx, "environment-id", "API_KEY", "value", "", "", "")
    if err != nil {
        log.Fatal(err)
    }
}
```

The base URL is the server root, without `/api`. All methods take `context.Context` as their first argument and return `(result, error)`. A nil `HTTPClient` uses a shared client with a 30-second timeout. Set `HTTPClient` to customize timeout or TLS configuration; HTTPS certificate verification is enabled by default.

## Generic management requests

`API(ctx, method, segments, body, query, stepUp...)` returns `(json.RawMessage, error)`. Segments are relative to `/api` and encoded individually; `query` is `url.Values` and preserves repeated values. For example, `client.API(ctx, "GET", []string{"capabilities"}, nil, nil)` discovers public route templates. Use `[]string{"envs", envID, "integrations"}` to list an environment's integrations, or pass a JSON-compatible body with POST, PUT or PATCH.

Supported methods are GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS. Empty success responses return nil data. HTTP failures retain status and raw body in `APIError`. Generic requests reject malformed encoding, controls, backslashes, URL-like segments and traversal, including repeatedly encoded traversal. Redirects are disabled using a copy of the configured HTTP client; its original redirect policy is not mutated. Named wrappers retain their existing behavior.

The server applies the same scopes, roles, environment restrictions and workspace membership as direct HTTP requests. Workspace management with OAuth additionally requires `org:admin`; discovery does not grant access. Do not log response bodies containing credentials.

The optional final variadic argument accepts at most one existing verification grant. It sends `X-OpenWarp-Step-Up` for that request only and must contain 1-512 printable ASCII characters. The Bearer credential and the configured HTTP client are unchanged. The SDK does not complete or bypass verification.

Methods, with the context argument omitted here:

- `Me()` returns `map[string]any`.
- `Orgs()`, `Apps(org)`, `Envs(app)` return `[]Org`, `[]App`, `[]Env`.
- `Secrets(env)` returns `[]Secret` from the response envelope.
- `GetSecret(env, key)` returns the unique case-insensitive key match as `Secret`. `GetSecretAtPath(env, key, path)` also matches the exact path.
- `SetSecret(env, key, value, path, secretType, comment)` returns the deployment response as `map[string]any`, including `sync_errors`. Empty path and type use `/` and `secret`. Tags are sent as an empty string.
- `DeleteSecret(env, key)` resolves the ID first, then returns the deletion response as `map[string]any` (nil for an empty response). `DeleteSecretAtPath(env, key, path)` selects the exact path.
- `Export(env)` returns `map[string]any` containing `text` and `secrets`.
- `Leases(env)` returns `[]Lease`.
- `CreateLease(env, name, ttlSecs)` returns `Lease`. Pass `3600` for a one-hour lease.
- `Audit(org)` returns `[]map[string]any`.

Get and delete without a path remain compatible for keys unique across paths. AtPath methods match paths verbatim: `/team/`, `/team`, and `/TEAM/` are distinct. Pass `/` for root; unlike `SetSecret`, AtPath lookup does not normalize an empty path to root. Missing matches return `*APIError` with status 404 and an empty body; multiple matches return status 409, including multiple records at an explicitly selected path. Neither error sends a delete request. These methods read every reported page and reject invalid pagination or more than 100,000 records with status 0. A legacy initial response without pagination metadata is treated as complete. A response with only `total` is accepted when it equals the returned count; other incomplete metadata is rejected. Pages are not a snapshot, so concurrent changes can affect selection. `Secrets(env)` still returns the first page. HTTP failures return `*APIError` with `Status`, `Message`, and raw text `Body`. Invalid JSON also returns `*APIError` with the response status. Use `errors.As` to inspect it. Transport and context failures retain their standard Go errors. There are no retries. Do not log error bodies or secret values.

Run the local HTTP mock tests from this directory:

```sh
go test ./...
```
