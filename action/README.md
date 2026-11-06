# OpenWarp export action

A dependency-free Node 20 JavaScript action that exports an OpenWarp environment
to a file. It calls `GET {base-url}/api/envs/{env-id}/export` with a bearer token.
The server must allow the token to read secrets in that environment.

| Input | Required | Default | Meaning |
| --- | --- | --- | --- |
| `base-url` | yes | none | OpenWarp server URL; use HTTPS outside local testing |
| `token` | yes | none | Bearer token with environment access and secrets read permission |
| `env-id` | yes | none | Environment ID, encoded as one URL path segment |
| `output-file` | no | `.env` | Workspace-relative or absolute destination path |
| `format` | no | `dotenv` | `dotenv` writes returned `text` unchanged; `json` writes the `secrets` array |
| `mask` | no | `true` | Register every exported value with the runner's `add-mask` command |

The `count` output is the number of exported secrets. No `@actions/core`, npm
installation, or build step is needed. The action uses built-in fetch and writes
outputs to `GITHUB_OUTPUT`. Missing inputs, invalid formats, and HTTP errors fail
the step. HTTP failures include the status and response body. The token is always
masked; exported values are masked unless `mask` is false. Empty values have no
maskable content. Redirects are rejected instead of forwarding credentials.

## Workflow example

This example runs in a checkout of the OpenWarp repository:

```yaml
name: Export configuration
on: workflow_dispatch
permissions:
  contents: read
jobs:
  export:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Fetch environment
        id: openwarp
        uses: ./action
        with:
          base-url: ${{ vars.OPENWARP_BASE_URL }}
          token: ${{ secrets.OPENWARP_TOKEN }}
          env-id: ${{ vars.OPENWARP_ENV_ID }}
          output-file: .env
          format: dotenv
          mask: 'true'
      - name: Report count
        env:
          SECRET_COUNT: ${{ steps.openwarp.outputs.count }}
        run: printf 'Exported %s secrets\n' "$SECRET_COUNT"
      - name: Remove exported secrets
        if: always()
        run: rm -f .env
```

In another repository, reference `hongkongkiwi/openwarp/action` at a reviewed
commit SHA instead of `./action`. The output contains plaintext secrets; do not
print it, commit it, cache it, or upload it as an artifact. Files are written with
mode 0600, including existing files. Masking only affects logs, not file contents.
The action does not inject secrets into later steps' environments or parse the
server's dotenv text. Consume the file with your application's configuration
loader, not by executing it as a shell script. Use trusted steps and a trusted
output path; parent directories are created if needed.

## Verification

```sh
node --check action/index.js
```
