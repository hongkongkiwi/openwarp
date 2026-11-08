# Integrations

Integrations push shared secrets from a standard SSE environment to another platform. Configuration is stored encrypted under the environment key. The server decrypts values before sending them, so both the server and destination are trusted with plaintext.

## Sync behavior

- Create an integration under an environment, then sync manually or through an environment deployment.
- Shared base values are the source. Personal overrides and sealed values are excluded.
- E2E environments do not provide the server-readable values used by this workflow.
- Provider operations can partially succeed. Inspect both the sync response and remote state before retrying.
- Path-restricted callers cannot manage or manually sync integrations. Their secret writes, deletes and restores do not trigger automatic sync. An unrestricted operator must sync separately; filtered subsets are never deployed as full-environment mirrors. See [path policies](WORKLOADS.md#restrict-secret-paths).
- Key naming (`prefix`, `suffix`, `name_template`) applies to every adapter. Dry-run, key filters and mirror behavior depend on the adapter.

The implementations live in [`integrations.rs`](../crates/server/src/integrations.rs). This guide describes OpenWarp's configured requests, not a guarantee that every provider API version or account plan accepts them. Validate with a non-production target before relying on a destination.

## Create and sync

Use the console or an authenticated API client. This example stores a dummy GitHub configuration; replace values only in a protected local file or request mechanism:

```json
{
  "name": "Repository secrets",
  "kind": "github",
  "config": {
    "token": "REPLACE_WITH_PROVIDER_TOKEN",
    "owner": "REPOSITORY_OWNER",
    "repo": "REPOSITORY_NAME"
  }
}
```

Save it as a private `integration.json`, then:

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer $OPENWARP_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @integration.json \
  "$OPENWARP_HOST/api/envs/$ENV_ID/integrations"
```

Use the returned integration ID:

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $OPENWARP_TOKEN" \
  "$OPENWARP_HOST/api/integrations/$INTEGRATION_ID/sync"
```

Sync can write remote secrets. Obtain the appropriate approval before executing it. Integration listing omits decrypted configuration; keep provider credential recovery in your own secret store.

| Operation | Endpoint |
| --- | --- |
| List/create | `GET` / `POST /api/envs/{env_id}/integrations` |
| Update/delete | `PATCH` / `DELETE /api/integrations/{id}` |
| Sync | `POST /api/integrations/{id}/sync` |
| Test | `POST /api/integrations/{id}/test` |

Test is implemented for `trigger`, `instabox`, `boat`, `daytona`, `1password`, `aws_secrets_manager`, `aws_parameter_store`, `dokploy`, `caprover`, `portainer`, `docker_swarm`, `bitbucket`, `circleci`, `teamcity`, `travisci`, `terraform_cloud`, `qovery`, `laravel_forge`, `openwarp`, `devin`, `cloudflare_secrets_store`, `octopus_deploy`, `azure_devops`, `cursor`, `scaleway_secret_manager`, `azure_app_configuration`, `vultr`, `hetzner`, `linode`, and `digitalocean_ssh`. Other kinds return 501. A sync is not a harmless substitute for Test.

PostgreSQL dynamic leases use TLS by default and now require the server to accept TLS instead of falling back to plaintext. A deployment that intentionally uses plaintext must explicitly configure `sslmode=disable`; use it only on a trusted network. This transport change also affects existing dynamic-lease configurations that relied on the driver's previous `prefer` fallback.

## Static PostgreSQL password rotation

This rotation schedule changes the password of an existing PostgreSQL login role, then saves it to an existing SSE value of type `secret`, `config` or untyped. SSH keys and sealed values are rejected both when the schedule is created and again before any remote connection during execution. It does not create roles, grant privileges or support MySQL.

Create with `POST /api/envs/{env_id}/rotations` and `rotations:write` authority:

```json
{
  "key": "DATABASE_PASSWORD",
  "path": "/payments/",
  "interval_secs": 86400,
  "config": {
    "kind": "postgres-static",
    "connection": "postgres://ADMIN:REPLACE_WITH_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=require",
    "username": "payments_login"
  }
}
```

The example is a request shape, not an executed provider configuration. Use a protected request file, not shell history, for real admin credentials. The server stores configuration encrypted under the environment key. Give the PostgreSQL administrator only the authority needed to change the target role's password. Use an administrator distinct from the role being rotated so retries can still connect after a password change.

The connection URL requires one TCP host and explicit administrator credentials. Unix sockets, `hostaddr` and multi-host connections are refused. The parsed driver's host must match a comma-separated `OPENWARP_ALLOWED_DB_HOSTS` entry, either a hostname/IP or a host-and-port pair. Use explicit ports to narrow the allowance. Transport is decided from the parsed URL, not text matching: the native server requires `sslmode=require` and rejects the driver default (`prefer`) and any explicit `sslmode=prefer`, so the connection cannot silently fall back to plaintext. `sslmode=disable` is accepted only for a literal loopback IP (`127.0.0.1` or `::1`) outside `OPENWARP_ENV=production`; hostnames such as `localhost` do not qualify. Static PostgreSQL rotation is native-only. Workers reject its configuration and do not claim or execute its schedules. Do not use host aliases to create multiple schedules for the same remote role. The database uniqueness guard identifies targets by configured host, port and username, not DNS equivalence.

The scheduler first persists an encrypted pending password, then issues a fixed, quoted `ALTER ROLE ... PASSWORD ...`, then updates the local secret. It clears the pending password only after local storage succeeds. On an uncertain remote outcome or failed local save, retries reuse the same candidate instead of generating a second password. A failure that created or retained a pending password is recorded as `rotation.failed_pending_retained`; a rejection before the candidate exists, such as an incompatible target type or refused transport, is recorded as `rotation.failed`. The remote password may already have changed even when the local value is old.

A missing or incompatible local target, or an unavailable environment key, advances the next attempt by the schedule interval (at least 60 seconds) and records a failure without creating a pending password or taking an execution claim. Concurrently claimed or rescheduled work is left unchanged. Environment point-in-time restore commits its secret and history changes together and returns 409 without partial changes if a static rotation has a pending password or execution claim.

For recovery, keep the schedule and its encrypted pending state, restore connectivity or local storage, and retry with `POST /api/rotations/{id}/run`. The response `{scheduled:true,id}` means the schedule is due, not that PostgreSQL or provider sync succeeded. Inspect audit records, local secret state and remote login before resuming consumers. Do not delete and recreate a pending schedule, manually replace its pending ciphertext, or restore an old database while consumers keep using the remote database: those actions can lose the candidate needed to reconcile the two sides. Rotation hooks and provider sync run after the local save and are not transactional with the remote password update.

An execution also holds a non-expiring durable `execution_token`. Manual Run can queue another due time but cannot replace that claim. A completed local-storage failure releases its claim and can be retried normally with the same pending password. A remote query error, timeout, interrupted task or crash can retain the claim because PostgreSQL may still be finishing the operation. There is no automatic TTL takeover or API to force-release an active claim. Deleting its schedule, environment or application returns 409 while a pending password or execution claim exists.

For a retained execution claim, first stop every OpenWarp replica and maintenance worker using this database. Verify at the target PostgreSQL server that the old rotation connection and statement are no longer running; terminate that session if necessary and confirm it is gone. Back up the OpenWarp database. Only while all workers remain stopped, clear the exact schedule's claim with an operator SQL session:

```sql
UPDATE rotation_schedules SET execution_token='' WHERE id='SCHEDULE_ID';
```

Preserve `pending_enc`, `config_enc` and the target secret. Restart one worker and request Run for that same schedule. Verify the retry reconciles the pending password before restoring other replicas or deleting anything. If remote quiescence cannot be established, leave the claim in place. This manual recovery statement was inspected, not executed against a production database.

`GET /api/envs/{env_id}/rotations` lists metadata without revealing connection credentials or pending passwords. E2E/delegated environments and sealed secrets are not supported. See [API](API.md#rotation-schedules) for schedule endpoints.

## Provider configuration

Fields below are the strings consumed by each adapter unless stated otherwise. Supply nonempty credentials and target IDs even where validation is deferred to a remote API. Optional `base_url` overrides exist for most HTTP adapters; AWS uses `endpoint`, Kubernetes uses `api_server`, Vault uses `addr`, and generic webhooks use `url`.

| Kind | Credential and target fields | Destination behavior |
| --- | --- | --- |
| `github` | `token`, `owner`, `repo` | Repository Actions secrets, encrypted with the repository public key |
| `gitlab` | `token`, `project_id` | Project variables; optional `base_url` includes the API prefix |
| `vercel` | `token`, `project_id`; optional `team_id`, `target`, `type` | Defaults to encrypted variables targeting production, preview, and development; `target` accepts `all`, a name, or an array, and `type` accepts `plain`, `encrypted`, or `sensitive` |
| `netlify` | `token`, `site_id` | Site variables with all-context requests |
| `cloudflare` | `token`, `account_id`, `script_name` | Worker secret bindings |
| `cloudflare_pages` | `token`, `account_id`, `project` | Production deployment configuration variables |
| `heroku` | `token`, `app` | App config vars |
| `render` | `token`, `service_id` | Service environment variables |
| `flyio` | `token`, `app` | App secrets through the Machines endpoint |
| `railway` | `token`, `project_id`, `environment_id`, `service_id` | GraphQL variable collection update |
| `digitalocean` | `token`, `app_id` | Updates service envs within the App Platform spec |
| `supabase` | `token`, `project_ref` | Project secrets |
| `nomad` | `token`; optional `base_url` | Nomad variable at `openwarp/default`; default server is local port 4646 |
| `coolify` | `token`, `app_uuid` | Application environment variables, not preview variables |
| `aws_secrets_manager` | `region`, `access_key_id`, `secret_access_key`; optional `session_token`, `role_arn`, `sts_endpoint`, `endpoint`, `kms_key_id`, `prefix`, `secret_id`, `mapping`, `force_delete` | One secret per key by default, or one JSON secret when `secret_id` is set (many-to-one). Mirror prunes managed names. |
| `aws_parameter_store` | `region`, `access_key_id`, `secret_access_key`, `path_prefix`; optional `session_token`, `role_arn`, `sts_endpoint`, `endpoint`, `type`, `tier`, `kms_key_id` | One SecureString parameter per key under the path. Mirror prunes managed names. |
| `1password` | `connect_url`, `token` (or `access_token`), `vault_id` (or `vault`); optional `value_label`, `category` | One 1Password item per key through a Connect server; the item title is the key and the value goes into the labelled concealed field. `onepassword` is accepted as an alias. |
| `dokploy` | `base_url`, `api_key`, plus exactly one of `application_id` or `compose_id`; optional `redeploy` | Merges values into the application or compose env string and optionally redeploys |
| `caprover` | `base_url`, `app_name`, and `password` or `token` | Updates the app's environment variables through CapRover API v2 |
| `portainer` | `base_url`, `api_key`, `endpoint_id`; `stack_id` or `stack_name` | Updates a Compose or Swarm stack's environment variables without changing its stack file |
| `docker_swarm` | `api_url`, plus `ca_cert`, `client_cert` and `client_key` for TLS; optional `api_version` | Docker Swarm secrets through the Docker Engine API. Docker secrets are immutable, so existing values are deleted and recreated |
| `bitbucket` | `workspace`, `repo_slug`, and `token` or `username` plus `password` | Repository Pipelines variables; optional `base_url` |
| `circleci` | `project_slug` (`gh/org/repo`), `token` | Project environment variables. Existing names are deleted and recreated because the API has no update call |
| `teamcity` | `base_url`, `token` (or `username` plus `password`); `project_locator` or `build_type_locator` | Project or build-type parameters |
| `travisci` | `repo` (`owner/name`), `token` | Repository environment variables |
| `terraform_cloud` | `token`, `workspace_id`; optional `category` (`env`), `sensitive` | Workspace variables in the configured category |
| `qovery` | `token`, `organization_id`, `project_id`, `environment_id`; optional `scope` (`ENV`) | Environment variables |
| `laravel_forge` | `token`, `organization`, `server_id`, `site_id` | Merges and writes the site `.env` file |
| `openwarp` | `base_url`, `token`, `env_id` | Deploys to another OpenWarp environment; mirror deletes managed names |
| `devin` | `token`, `org_id` | Organization key-value secrets. Existing secrets are recreated because values are not returned |
| `cloudflare_secrets_store` | `token`, `account_id`, `store_id`; optional `scopes` (`["workers"]`) | One store secret per key, up to 64 KiB per value; existing secrets are recreated because values are write-only |
| `octopus_deploy` | `base_url`, `api_key`, `project_id`; optional `space_id` (`Spaces-1`), `scope` | Rewrites the project variable collection |
| `azure_devops` | `organization`, `project`, `group_id`, `token` | Rewrites a pipeline variable group with secret values |
| `cursor` | `token`; `environment_id` for environment scope, omit it for team scope; optional `secret_type`, `repos` | Cloud Agents environment or team secrets. Values are never returned, so existing names are overwritten |
| `huggingface` | `token`, `namespace`, `repo`; optional `target` (`secrets`, the default, or `variables`) | One Space secret or variable per key. Secret values are write-only, so existing names are overwritten; variables are readable and unchanged values are skipped. Names must match `[A-Za-z][_A-Za-z0-9]*`. Initial import works for variables only |
| `ssh` | `host`, `known_hosts`; one of `identity_file`, `private_key` or `password`; optional `user`, `port`, `files` | Writes secret folders to files on the host. See below |
| `scaleway_secret_manager` | `region` (`fr-par`, `nl-ams` or `pl-waw`), `secret_key`, `project_id`; optional `path` | One opaque secret per key. A changed value adds a version and disables the previous one; payloads are base64 and capped at 64 KiB |
| `azure_app_configuration` | `endpoint`, `id` (access key id), `secret` (base64 access key value); optional `label` | One key-value per key, written with the HMAC-SHA256 scheme. An empty label targets key-values with no label |
| `vultr` | `api_key` | Account SSH keys. Each secret value must be a single-line OpenSSH public key; the secret name is the key name. A changed key is patched in place |
| `hetzner` | `token` | Account SSH keys, taken only from secrets of type `ssh_key`. The API cannot replace key material, so a changed key is deleted and created again and its numeric id changes |
| `linode` | `token` | Account SSH keys, taken only from secrets of type `ssh_key`. A changed key is deleted and created again, so its id changes |
| `digitalocean_ssh` | `token` | Account SSH keys at `/v2/account/keys`, taken only from secrets of type `ssh_key`. Distinct from `digitalocean`, which updates an App Platform spec. A changed key is deleted and created again |
| `gcp_secret_manager` | `project` and either `token` or `service_account_json`; optional `tags` | Creates/versions secrets; lowercases names and replaces underscores with hyphens; tags become labels |
| `azure_key_vault` | `vault` (or `base_url`) and either `token` or `tenant_id`, `client_id`, `client_secret`; optional `token_endpoint`, `mapping`, `secret_name`, `absent`, `tags` | Writes individual secret versions or one JSON blob; lowercases individual names and replaces underscores with hyphens |
| `kubernetes` | `token`, `api_server`, `namespace`, `secret_name` | Writes an Opaque Secret; creates it after a not-found response |
| `hashicorp_vault` | `token`, `addr`, `path` | Sends a `{data: ...}` payload to the configured Vault API path |
| `webhook` | `url`; optional `token`, `signing_secret` (or `secret`) | POSTs `{secrets: {NAME: value}}`. `token` is sent as a bearer header. A signing secret adds `X-OpenWarp-Timestamp` and `X-OpenWarp-Signature: t=<unix>,v1=<hex>`, the HMAC-SHA256 of `timestamp.body` |
| `trigger` | `token`, `project_ref`, `target_env`, or a `targets` array | Trigger.dev environment variables; see below |
| `instabox` | `api_key` (or `token`), `org` | Organisation secrets with proxy or environment delivery |
| `boat` | `api_key`; optional `environment`, `org` | Sandbox environment variables |
| `daytona` | `api_key`; `organization_id` for JWT keys | Organisation vault secrets and optional sandbox mounts |

The AWS adapters sign requests directly. They do not use an SDK credential chain. Supply `region`, `access_key_id`, and `secret_access_key`; add `session_token` for temporary credentials, or `role_arn` to assume a role first (`sts_endpoint` overrides the STS endpoint). Renaming transformations can collide, such as names distinguished only by underscores versus hyphens. Review remote names before syncing.

Some adapters use fixed destination contexts. Vercel defaults to all three listed contexts but accepts `target` and `type`; Cloudflare Pages writes production configuration. An OpenWarp environment name does not automatically select a matching remote environment.

The `kubernetes` adapter pushes values to the cluster API. For pods that pull values themselves, or for External Secrets Operator, see [Kubernetes](KUBERNETES.md).

## Advanced sync options

These options apply to server-managed syncs. Customer-run delegated syncs use a separate runner and do not yet support source path selection, per-secret metadata tags, or managed Azure Key Vault behavior.

### Source selection

`paths` selects source folders by exact path; an empty or absent array selects all. Set `include_subfolders: true` to include descendants, including every folder when `/` is selected.

### Key naming

Naming is off by default and applies to every adapter. It renames a key on the way to the destination, and imports strip the same affixes so remote names map back to local keys. Values are never rewritten.

| Field | Meaning |
| --- | --- |
| `prefix` | Prepended to every selected key; accepts `{{environment}}` |
| `suffix` | Appended to every selected key; accepts `{{environment}}` |
| `case` | `upper` or `lower`; rewrites the source key before prefix, suffix or template substitution. Defaults to preserving case |
| `name_template` | Replaces prefix and suffix when set. Must contain `{{secretKey}}` exactly once, and may use `{{environment}}` |
| `key_schema` | Alias for `name_template`; `name_template` takes precedence when both are set |

For example, `"prefix": "APP_"` and `"suffix": "_{{environment}}"` write `API_KEY` as `APP_API_KEY_production`. The equivalent template is `"name_template": "APP_{{secretKey}}_{{environment}}"`. For Terraform-style names, `"prefix": "TF_VAR_", "case": "upper"` writes `db_host` as `TF_VAR_DB_HOST`; `case` applies to the key only, so the prefix keeps its spelling. This is the same idea as Infisical's Key Schema: choose a pattern that only matches the keys this integration should own. A mirror sync deletes only names it previously managed, so unrelated destination keys are left alone.

AWS Secrets Manager, Azure Key Vault, and GCP Secret Manager accept a `tags` object of static string values and copy per-secret metadata tags. Comma-separated `key=value` entries become tags; bare entries have empty values. Static tags take precedence. AWS and Azure many-to-one mappings use static tags only. GCP converts tags to lowercase labels, replaces unsupported characters with underscores, and prefixes names that do not start with a letter with `tag_`. GCP label updates on existing secrets replace their label set, including clearing all labels when no tags remain. For duplicate selected names, GCP writes the first shared value and its metadata once. AWS tags are merged. Azure writes tags on the new secret version.

The stateful adapters (Trigger.dev, Instabox, Boat, Daytona, 1Password, both AWS adapters, Azure Key Vault, Dokploy, CapRover, Portainer, Docker Swarm, Bitbucket, CircleCI, TeamCity, Travis CI, Terraform Cloud, Qovery, Laravel Forge, OpenWarp, Devin, Cloudflare Secrets Store, Octopus Deploy, Azure DevOps, Cursor, Scaleway Secret Manager, Azure App Configuration, Vultr, Hetzner and SSH files) also share these options:

| Field | Meaning |
| --- | --- |
| `mode` | Use `upsert` by default; `mirror` can delete names previously managed by this integration |
| `dry_run` | Boolean; inspect intended changes without remote mutations |
| `include_keys` | Array of source keys to include; empty means all |
| `exclude_keys` | Array of source keys to omit |
| `base_url` | Override the adapter's API base for a compatible service |
| `auto_sync` | Default true. Set false to skip automatic runs on deploy, rotation, proposal, delete, restore and point-in-time restore before sync-option validation; manual Sync still validates and runs |
| `initial_sync` | `overwrite` (default), `import_local` (keep local values) or `import_remote` (remote values win). Import runs on the first stateful sync and requires the root path `/` to be selected |
| `disable_secret_deletion` | Boolean; suppresses pruning and retains ownership of previously managed names |

Filters apply before naming. Mirror uses persisted managed-name state, not blanket deletion of every name on the remote service. Changing targets, prefixes, suffixes, templates or filters affects that state; review a dry run and remote inventory first. The remaining options are not supported by every row in the provider table.

`initial_sync` is limited to adapters that can return values: AWS Secrets Manager, AWS Parameter Store, 1Password, Dokploy, CapRover, Portainer, Bitbucket, TeamCity, Travis CI, Terraform Cloud, Qovery, Laravel Forge, Octopus Deploy, Azure DevOps, OpenWarp, Scaleway Secret Manager, Azure App Configuration, Vultr, Hetzner and Hugging Face Space variables. CircleCI, Devin, Cloudflare Secrets Store, Cursor and Hugging Face Space secrets reject import because their APIs never return values.

Several adapters cannot diff values and therefore rewrite existing entries on every sync: CircleCI, Devin, Cloudflare Secrets Store, Docker Swarm, Cursor and Hugging Face Space secrets. Octopus Deploy, Azure DevOps and Laravel Forge rewrite a collection document, preserving entries this integration did not manage. Plan for the write amplification and short gaps that a delete-and-recreate can cause.

## AWS Secrets Manager

The adapter signs its own SigV4 requests. It does not use an SDK credential chain, so supply `region`, `access_key_id`, and `secret_access_key`; add `session_token` for temporary credentials.

Two mappings are available:

- `mapping: "one_to_one"` (the default when `secret_id` is absent) writes one remote secret per key, using the key naming options. Missing names are created with `CreateSecret`; existing names receive a new version with `PutSecretValue`. Mirror deletes previously managed names with a seven-day recovery window unless `force_delete: true`.
- `mapping: "many_to_one"` (the default when `secret_id` is set) writes every value into one JSON `SecretString` at `secret_id`, creating the secret when it does not exist. Key naming and key filters apply to the JSON field names. Mirror is rejected because keys are not separate remote objects.

`kms_key_id` applies only when a secret is created. `role_arn` makes the adapter assume that role first, using the supplied base credentials and optional `external_id` and `sts_endpoint`; the resulting temporary credentials sign the sync. `endpoint` overrides the regional endpoint. One-to-one names are validated against the Secrets Manager character set and 512-byte limit before any write.

```json
{
  "region": "us-east-1",
  "access_key_id": "REPLACE_WITH_KEY_ID",
  "secret_access_key": "REPLACE_WITH_SECRET",
  "mapping": "one_to_one",
  "prefix": "app/prod/",
  "mode": "upsert",
  "dry_run": true
}
```

## Azure Key Vault

`mapping: one_to_one` writes each selected key as a secret. `mapping: many_to_one` writes the selected keys as one JSON value in `secret_name` and accepts static tags only. Many-to-one cannot use mirror or `absent: disable`.

Both mappings explicitly enable each newly written version in the PUT request. `absent: disable` lists version metadata for previously managed names missing from the source, then disables every returned version with a versioned PATCH, including versions already disabled. It does not read secret values or assume version ordering. Pagination stays on the same vault and secret versions path and fails on cycles or more than 100 pages; version IDs must match the configured vault and secret. The credential needs list-version and update permissions. Discovery or update failures fail the sync rather than silently leaving versions enabled; earlier provider writes may already have succeeded.

Disabled secrets remain in managed state under their logical names, not version IDs; `disabled` counts logical names. Missing secrets or empty version lists are dropped from managed state. Returning names receive a new enabled version, while older disabled versions stay disabled. It cannot be combined with `mode: mirror`; mirror deletes previously managed missing names. `disable_secret_deletion` suppresses both operations and retains ownership. Dry runs do not exchange credentials, discover versions or mutate the vault. Azure Key Vault supports only `initial_sync: overwrite`; initial import is not implemented.

## AWS Parameter Store

Each selected key becomes one parameter. `path_prefix` is prepended to the prefixed key, so `path_prefix: "/app/prod"` and key `API_KEY` produce `/app/prod/API_KEY`. Values are written with `PutParameter` and `Overwrite: true`. `type` defaults to `SecureString`; `kms_key_id`, `tier`, and `session_token` are supported. Standard tier values over 4096 bytes are rejected before any write; use `tier: "Advanced"` for larger values.

Listing uses `GetParametersByPath` when `path_prefix` is set and `DescribeParameters` otherwise, following pagination. Mirror deletes only names this integration previously managed.

```json
{
  "region": "us-east-1",
  "access_key_id": "REPLACE_WITH_KEY_ID",
  "secret_access_key": "REPLACE_WITH_SECRET",
  "path_prefix": "/app/prod",
  "type": "SecureString",
  "mode": "upsert",
  "dry_run": true
}
```

## 1Password Connect

Kind `onepassword` writes through a self-hosted 1Password Connect server. Connect is required: 1Password Service Accounts do not expose an equivalent REST API for server-side writes. Config: `connect_url`, `token` (or `access_token`), `vault_id` (or `vault`), and optional `value_label` (default `value`) and `category` (default `API_CREDENTIAL`).

Each key becomes one item. The item title is the key and the value is stored in the concealed field whose label matches `value_label`. Existing items are read and replaced, preserving their other fields, sections, tags and URLs. Mirror deletes only titles this integration previously managed.

```json
{
  "connect_url": "https://connect.example.invalid",
  "token": "REPLACE_WITH_CONNECT_TOKEN",
  "vault_id": "REPLACE_WITH_VAULT_ID",
  "value_label": "value",
  "mode": "upsert",
  "dry_run": true
}
```

## Dokploy

Kind `dokploy` reads the application or compose env string, merges the desired keys into it, and saves the result. Unrelated existing variables survive. Supply `base_url`, `api_key`, and exactly one of `application_id` or `compose_id`. `redeploy: true` triggers a redeploy after saving.

Dokploy stores the environment as one text field, so values containing line breaks, carriage returns or NUL are rejected. Mirror removes only keys this integration previously managed. The API key is sent in `x-api-key`.

## CapRover

Kind `caprover` authenticates with `password` through `POST /api/v2/login`, or accepts an existing `token`. It lists `user/apps/appDefinitions`, finds `app_name`, merges the desired values into that app's `envVars`, and posts the full app definition back so unrelated settings survive. Names use shell-style letters, digits and underscores. Mirror removes only previously managed keys. The token is sent in `x-captain-auth`.

## Portainer

Kind `portainer` updates a Compose or Swarm stack's environment variables, not Docker Swarm secrets. Supply `base_url`, `api_key`, `endpoint_id`, and `stack_id` or `stack_name`. Sync reads the stack file with `GET /api/stacks/{id}/file`, merges the stack `Env` array, and calls `PUT /api/stacks/{id}?endpointId=...` with the unchanged `StackFileContent`. Kubernetes stacks are not supported. A Git-backed stack can reject the update with 409; redeploy it through Portainer instead.

## Docker Swarm

Kind `docker_swarm` uses the Docker Engine API and therefore requires Swarm. Standalone Docker has no API-managed secret store; use Compose env files or `openwarp run` for that case. Config: `api_url` (`http://` or `https://`), optional `api_version` (default `v1.47`), and `ca_cert`, `client_cert`, `client_key` as PEM strings for TLS. `insecure: true` disables certificate verification and should be limited to isolated test hosts.

Secret names must be 1-64 characters of letters, digits, underscore, dot or dash. Docker never returns secret values and secrets are immutable, so a changed value deletes the existing secret and creates it again; the name is briefly absent in between. Mirror deletes only previously managed names.

## Cloud machine providers and AI environments

OpenWarp syncs secrets only where the remote service exposes a secret or environment-variable API. Several machine providers accept environment variables or SSH keys only when a machine is created, then offer no way to update them. Those are not secret-sync destinations.

- Covered by an existing adapter: Daytona, Boat, Instabox, Cloudflare, Railway, Vercel, DigitalOcean App Platform, Docker Swarm.
- SSH keys only: Vultr, Hetzner Cloud, Linode and DigitalOcean keep account SSH keys but no general secret store. `vultr`, `hetzner`, `linode` and `digitalocean_ssh` sync only secrets whose type is `ssh_key` and ignore every other secret, so a generic secret never reaches a key API. The value must be a single-line OpenSSH public key, and saving one that is not is rejected. Only Vultr can change key material in place; the other three delete and recreate a changed key, which issues a new id.
- Machine lifecycle only, with no secret or key update API: AWS EC2, Google Compute Engine, DigitalOcean droplets, plain Docker, E2B, Modal, CodeSandbox, Runloop, Blaxel, Tensorlake, Freestyle, RunPod and AWS AgentCore. The `boxd` provider in pandacode PR 336 belongs to the same group. Linode keeps account SSH keys too, but has no adapter yet. An SSH host is reachable as the `ssh` file adapter, which writes files rather than provisioning the machine.
- Cursor Cloud Agents exposes environment and team secret endpoints, so it is supported as `cursor`.
- Grok Bot Vault and ChatGPT/Codex cloud environments document their environment variables and secrets as settings, not as a public API. They have no adapter.
- Keeper requires Keeper Commander running in Service Mode; it has no plain REST secret API in the documented integration path.

Adding the machine-only providers would require a machine-provisioning feature that creates or updates a machine and injects its environment, which is a different product surface from secret sync.

## SSH files

Kind `ssh` logs into a host and writes secret folders to files, which is the remote equivalent of an env file. It needs `host` and `known_hosts`, plus one of `identity_file` (a path to a private key on the server), `private_key` (the PEM itself) or `password`. `known_hosts` is the server's public key line, or a path to a known_hosts file; a host whose key does not match is refused, so the integration cannot be pointed at a different machine by surprise. `user` defaults to `root` and `port` to `22`. Password auth needs `sshpass` on the server.

`files` maps folders to files. Each entry has `path`, `format` (`dotenv`, also accepted as `env` or `.env`, plus `json`, `yaml`, `csv` or `export`) and `folders`, the secret paths that feed it. `dotenv`, `yaml` and `export` start with a `# Synced by OpenWarp at <time>` line unless `comment` is false. `json` and `csv` have no comment syntax, so they never carry one. CSV writes a `key,value` header and quotes a cell that contains a comma, quote or line break. A folder matches itself and everything under it, so `/app` also takes `/app/web`. One file with no `folders` takes every secret. A key that lands in two files is rejected, because one name cannot carry two values. `file_mode` (octal, for example `600`) and `owner` (`user` or `user:group`) are applied after the write.

With no `files`, `path` and `format` describe the single file. The file is written to a sibling and renamed into place, so a dropped connection does not empty it. Mirror removes only names this integration wrote to that file; other lines in the file survive. `initial_sync` reads the files back.

```json
{
  "host": "app.example.invalid",
  "user": "deploy",
  "identity_file": "/etc/openwarp/deploy_key",
  "known_hosts": "app.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnly",
  "files": [
    {"path": "/srv/app/.env", "format": "dotenv", "folders": ["/app"], "file_mode": "600"},
    {"path": "/srv/db/env.json", "format": "json", "folders": ["/db"]}
  ]
}
```

## Kamal

Kamal has no server API and no central secret store. It reads `.kamal/secrets` on the machine that runs the deploy. Generate that file from OpenWarp at deploy time with `openwarp export --format dotenv`, run the deploy through `openwarp run -- kamal deploy`, or point Kamal's secret commands at the 1Password or AWS integration. A server-side `kamal` adapter is intentionally not provided.

## Trigger.dev

A single-target configuration:

```json
{
  "token": "REPLACE_WITH_TOKEN",
  "project_ref": "REPLACE_WITH_PROJECT_REF",
  "target_env": "staging",
  "mode": "upsert",
  "dry_run": true
}
```

The target environment is `dev`, `staging`, or `prod`; omitted targets default to `prod`. Fan-out uses `targets: [{project_ref, env, token}]`. A target without its own token uses the global token. Each target is processed separately, and a failure in any target makes the sync fail overall; it does not roll back already updated targets.

Sync lists variables, compares readable values, bulk-imports changes, and optionally deletes previously managed names. Test checks the first target, so it does not prove every fan-out destination works.

`mark_secret` cannot apply dashboard-style secret marking through the implemented import schema; the sync response reports that limitation. Use the provider dashboard where needed. This integration pushes OpenWarp values outward; it does not import remote secrets into OpenWarp.

## Instabox

```json
{
  "api_key": "REPLACE_WITH_INSTABOX_KEY",
  "org": "REPLACE_WITH_ORG",
  "delivery": "proxy",
  "hosts": ["api.example.invalid"],
  "mode": "upsert",
  "dry_run": true
}
```

`delivery` defaults to `proxy`. Supply allowed bare hostnames for proxy substitution. Empty hosts require the explicit `allow_all_hosts: true` exception; prefer a narrow host list. For `delivery: "env"`, use an empty hosts list.

Names must start with an ASCII letter or underscore, contain only letters/digits/underscores, and be at most 128 bytes. Reserved names and prefixes are rejected. Values are limited to 65,536 bytes; proxy values cannot contain line breaks or NUL. Host lists have a maximum of 32 entries.

Instabox does not return plaintext values. Sync imports the desired names and reports sends/replacements rather than claiming a value diff. Mirror deletes only previously managed names.

## Boat

```json
{
  "api_key": "REPLACE_WITH_BOAT_KEY",
  "environment": "base",
  "org": "REPLACE_WITH_SHARED_ORG",
  "upgrade": false,
  "mode": "upsert",
  "dry_run": true
}
```

The environment selector accepts a name or ID and defaults to `base`; `environment_id` is also recognised. Set `org` for a shared environment. Names must use shell-style letters, digits, and underscores, starting with a letter or underscore.

Sync reads the environment, writes variables, and can prune managed names. `upgrade: true` requests an environment upgrade after sync so existing sandboxes can receive the updated version. Without an upgrade, do not assume a running sandbox has the new values.

## Daytona

```json
{
  "api_key": "REPLACE_WITH_DAYTONA_KEY",
  "organization_id": "REPLACE_WITH_ORG_ID",
  "hosts": ["api.example.invalid"],
  "mode": "upsert",
  "dry_run": true
}
```

JWT-shaped keys require `organization_id`, sent in the organisation header. Optional `sandbox` selects a sandbox for managed-secret mounts. `hosts` is an array of allowed outbound host strings stored with each secret.

The adapter lists vault metadata, creates missing names, and patches existing values. Remote values are not returned, so replacements are not verified by plaintext comparison. The implementation requests a paginated list with a limit of 200 and falls back to the legacy list endpoint; it does not walk subsequent pages. Validate behavior before using a larger vault.

Vault mounts are distinct from rewriting an existing sandbox's process environment. Do not assume vault sync changes every running process's environment variables.

## Operational checks

1. Use a non-production target and least-privilege provider credentials.
2. Check the destination's naming, size, and context restrictions.
3. Use Test where implemented, then a dry run where supported.
4. Execute a controlled sync and inspect the remote result.
5. Check error responses and audit history; retry only after understanding partial writes.

Provider HTTP requests normally use a 30-second timeout and disable redirects. Reachability from your laptop does not prove reachability from the OpenWarp server. Validate custom endpoints and restrict outbound access at the network layer.

[Security model](SECURITY.md) · [Documentation index](README.md)
