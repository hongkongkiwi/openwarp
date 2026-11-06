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

Methods, with the context argument omitted here:

- `Me()` returns `map[string]any`.
- `Orgs()`, `Apps(org)`, `Envs(app)` return `[]Org`, `[]App`, `[]Env`.
- `Secrets(env)` returns `[]Secret` from the response envelope.
- `GetSecret(env, key)` returns the first case-insensitive key match as `Secret`.
- `SetSecret(env, key, value, path, secretType, comment)` returns the deployment response as `map[string]any`, including `sync_errors`. Empty path and type use `/` and `secret`. Tags are sent as an empty string.
- `DeleteSecret(env, key)` resolves the ID first, then returns the deletion response as `map[string]any` (nil for an empty response).
- `Export(env)` returns `map[string]any` containing `text` and `secrets`.
- `Leases(env)` returns `[]Lease`.
- `CreateLease(env, name, ttlSecs)` returns `Lease`. Pass `3600` for a one-hour lease.
- `Audit(org)` returns `[]map[string]any`.

Missing keys return `*APIError` with status 404 and an empty body. Duplicate keys across paths resolve to the first match in the server response. HTTP failures return `*APIError` with `Status`, `Message`, and raw text `Body`. Invalid JSON also returns `*APIError` with the response status. Use `errors.As` to inspect it. Transport and context failures retain their standard Go errors. There are no retries. Do not log error bodies or secret values.

Run the local HTTP mock tests from this directory:

```sh
go test ./...
```
