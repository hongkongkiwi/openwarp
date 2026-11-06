# Terraform provider for OpenWarp

Manages OpenWarp apps, environments, secrets and service tokens. The provider
is built on the Terraform Plugin Framework and follows [`../openapi.json`](../openapi.json).

It is not published to the Registry yet. Build it locally and point Terraform
at the binary with a development override.

## Build and install

```bash
go build -o terraform-provider-openwarp .
```

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "hongkongkiwi/openwarp" = "/absolute/path/to/terraform-provider"
  }
  direct {}
}
```

With a dev override, run `terraform plan` directly; `terraform init` warns that
the provider is overridden and is not needed.

## Credentials

```hcl
provider "openwarp" {
  host  = "https://secrets.example.com"
  token = var.openwarp_token
}
```

`host` and `token` fall back to `OPENWARP_HOST` and `OPENWARP_TOKEN`. The token
comes from `openwarp login`, a service token, or an OAuth access token. Service
tokens scoped to one environment can only manage that environment.

## Resources

### openwarp_app

| Argument | Type | Notes |
| --- | --- | --- |
| `org_id` | string, required | Forces replacement |
| `name` | string, required | |

Creates Development, Staging and Production automatically.

Import: `terraform import openwarp_app.x <app_id>` (searches the caller's
organisations for the id).

### openwarp_environment

| Argument | Type | Notes |
| --- | --- | --- |
| `app_id` | string, required | Forces replacement |
| `name` | string, required | Letters, digits, `-`, `_` |
| `restricted` | bool, optional | Only environment members and admins |
| `require_approval` | bool, optional | Direct deploys become admin-only |

Import: `terraform import openwarp_environment.x <env_id>`.

### openwarp_secret

| Argument | Type | Notes |
| --- | --- | --- |
| `env_id` | string, required | Forces replacement |
| `key` | string, required | Upper-case letters, digits, `.`, `-`, `_`; forces replacement |
| `value` | string, required, sensitive | |
| `path` | string, optional | `/` by default; forces replacement |
| `type` | string, optional | `secret` or `config` |
| `comment` | string, optional | |
| `tags` | string, optional | Comma-separated tags as the API stores them |

`version` is computed. Sealed secrets are not managed: the API never returns
their value.

Import: `terraform import openwarp_secret.x <env_id>:<KEY>` or
`<env_id>:<path>:<KEY>` for a non-root path.

### openwarp_service_token

| Argument | Type | Notes |
| --- | --- | --- |
| `app_id` | string, required | Forces replacement |
| `name` | string, required | Forces replacement |
| `env_id` | string, optional | Scopes the token; forces replacement |
| `token` | computed, sensitive | Shown once at creation |

Import: `terraform import openwarp_service_token.x <token_id>`. The plaintext
token cannot be recovered after creation; an imported token keeps an empty
value, so generate a new one if you need the secret.

## Data source

`openwarp_secret` reads a secret by `env_id`, `key` and optional `path`, and
exposes `value` (sensitive), `id`, `type` and `version`.

## Test

```bash
# Compiles the provider and the acceptance tests.
go test ./...

# Client round trip against a real server binary.
cargo build -p openwarp-server
OPENWARP_BIN="$PWD/../target/debug/openwarp-server" go test ./internal/client -v

# Acceptance tests. They need a running instance, a token and an org id.
export OPENWARP_HOST=http://127.0.0.1:8080
export OPENWARP_TOKEN=...
export OPENWARP_TEST_ORG_ID=...
TF_ACC=1 go test ./internal/provider -v -timeout 20m
```

## Publishing

The Registry expects a dedicated `terraform-provider-openwarp` repository with
signed releases for each platform. The module is self-contained here so it can
be moved with `git subtree` when that repository is created.
