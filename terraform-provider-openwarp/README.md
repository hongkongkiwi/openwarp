# OpenWarp Terraform provider scaffold

Go module using Terraform Plugin SDK v2 helper/schema. This is source scaffolding, not a published provider. It has not been built, dependency-resolved, schema-validated, or tested with Terraform. No go.sum is supplied because no dependencies were downloaded.

## Configuration

`base_url` is required, or supplied by `OPENWARP_BASE_URL`. Use the server origin with an optional deployment prefix, without `/api`, credentials, query, or fragment. `token` is required and sensitive, or supplied by `OPENWARP_TOKEN`. Use HTTPS in production. HTTP requests use Bearer authentication, a 30-second timeout, and no redirects. HTTP error diagnostics include only status, not response bodies that might contain secret data.

## Resource openwarp_secret

Required: `app_id`, `env_id`, `key`, `value`. Value is sensitive. Optional: `path` (default `/`), `type` (default `secret`), `comment` (default empty). Changes to app, environment, key, path, or type replace the resource. Type replacement accommodates the server's sealed-secret restrictions.

Create and Update validate environment membership through `GET /api/apps/{app}/envs`, list existing secrets to preserve unmanaged tags, then upsert one secret through PUT. Read lists environment secrets and matches key case-insensitively plus exact path. A successful list without a match clears the resource ID. Delete resolves the current secret ID with the same lookup before DELETE. Authorization and transport errors are reported rather than treated as absence. The server's PUT is an upsert: a pre-existing key/path can be adopted and overwritten. Do not manage the same secret with multiple resources or enable create_before_destroy for replacements sharing its identity.

Import is intentionally not implemented. App ownership cannot be recovered from the optional `env_id/key` import format using only the supplied routes. Configure a resource explicitly instead. Sync errors returned by PUT are not surfaced by this scaffold; deployment and downstream integration success are separate.

## Data source openwarp_secret

Required: `env_id`, `key`. Returns sensitive `value`, `path`, and `type`. A missing key or a key present at multiple paths is an error, rather than an arbitrary selection.

Sensitive values still reside in Terraform state. Encrypt and restrict the state backend, avoid committing state or secret variable files, and do not expose values through non-sensitive outputs. API-returned sealed or redacted values follow server behavior; this scaffold does not decrypt end-to-end encrypted environments.

See `examples/main.tf` for resource and data-source declarations. The example source address is a naming convention only. Local use requires building and configuring a Terraform CLI development override for that address after dependency downloads are authorized. No installation, build, Terraform init, plan, apply, or acceptance checks were run during scaffold creation.
