# CLI reference

The `openwarp` CLI authenticates to an instance, reads and writes secrets, and injects them into child processes. Commands use IDs rather than display names unless explicitly stated otherwise.

## Installation and help

```bash
cargo install --path crates/cli
openwarp --help
openwarp login --help
```

Without installing, use `cargo run -p openwarp-cli -- COMMAND`. Run installation from the repository root. Ensure Cargo's binary directory is on `PATH`.

## Host and token selection

Put top-level options before the subcommand:

```bash
openwarp --host "$OPENWARP_HOST" orgs
openwarp --host "$OPENWARP_HOST" --token "$OPENWARP_TOKEN" secrets --env ENV_ID
```

The environment variables provide the same options without repeating flags. Host selection uses the explicit option/environment, then the saved user configuration, then `.openwarp.json`, then `http://127.0.0.1:8080`. A saved user host can therefore override the project's host. Use an explicit host when switching instances, and provide credentials issued by that instance.

The top-level token option supplies a token for the current invocation. The separate `login --token` option persists token login.

## Authentication

| Method | Command | Use |
| --- | --- | --- |
| Browser OAuth | `openwarp login` | Interactive development |
| Existing token | `openwarp login --token "$SERVICE_TOKEN"` | Persist a service token |
| Machine identity | `openwarp login --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET"` | Universal Auth |
| Current identity | `openwarp whoami` | Inspect the authenticated account |
| Sign out | `openwarp logout` | Sign out and clear saved credentials |
| SSH certificates | `openwarp ssh cert --ca CA_ID --principal NAME` | Sign a public key for a granted principal |

Browser login uses PKCE and a temporary loopback callback port. Browser OAuth credentials can refresh automatically when saved refresh metadata is available. Service tokens and machine credentials do not become renewable OAuth sessions simply because you saved them; respect their expiry and reauthenticate as needed. Machine-issued tokens last one hour.

Avoid literal credentials in shell history. Even variable expansion into a command argument can expose that argument to local process inspection. Use a suitably protected automation environment.

### Credential storage

User configuration lives at `~/.openwarp/config.json`, or the path in `OPENWARP_CONFIG`. On macOS, the CLI uses the `security` command for Keychain access. On Linux it uses `secret-tool` and Secret Service. Accepted access and refresh tokens are removed from the JSON configuration copy when stored in the credential store.

If the credential store is unavailable or rejects storage, the file can contain tokens. `OPENWARP_NO_KEYRING=1` forces file storage. The CLI sets the containing directory to 0700 and the file to 0600 on Unix; those permissions are not a cross-platform guarantee. Choose a dedicated directory if overriding the configuration path.

## Project selection

```bash
openwarp orgs
openwarp apps --org ORG_ID
openwarp envs --app APP_ID
openwarp init --app APP_ID --env ENV_ID
```

`init` writes host, `app_id`, and `env_id` to `.openwarp.json` in the current directory. Commands with an app or environment selector use the corresponding value when the flag is omitted. The CLI reads the current directory's file; it does not promise to search parent directories. Inspect an existing file before replacing its defaults.

## Standard secret commands

| Command | Behavior |
| --- | --- |
| `secrets [--env ENV_ID]` | List secrets, redacting values |
| `secrets [--env ENV_ID] --show` | List readable plaintext values |
| `get [--env ENV_ID] KEY` | Print a value selected by key |
| `set [--env ENV_ID] KEY VALUE` | Write a secret at the root path |
| `delete [--env ENV_ID] KEY` | Delete the secret selected by key |
| `import [--env ENV_ID] FILE` | Import dotenv text |
| `export [--env ENV_ID] [--base] --format FORMAT` | Print exported secrets; `--base` skips your personal overrides |
| `run [--env ENV_ID] -- COMMAND...` | Launch a child with secret environment variables |

These are direct API operations, not console drafts. Access policy may reject writes or require a proposal. Use dummy values to learn the command shape:

```bash
openwarp set EXAMPLE_GREETING hello-openwarp
openwarp get EXAMPLE_GREETING
openwarp secrets --show
```

### Paths and secret names

Standard secret names are normalised to uppercase. Server validation accepts 1-128 characters from letters, digits, underscore, dot, and hyphen. A secret's identity also includes its path.

The CLI's standard `get` and `delete` commands select by key, not by path. If the same name exists in several paths, use the console or an API operation on the exact secret ID. `set` and the E2E CLI write at `/`; there is no documented CLI `--path` selector.

Names accepted by the secret store are not necessarily valid shell variable names or valid at every integration destination. For process injection, use conventional names such as `DATABASE_URL`.

### Import and export

Supported export formats are `dotenv` (default), `json`, `yaml`, and `shell`:

```bash
openwarp export --format json
openwarp export --format dotenv
openwarp export --base --format shell --env ENV_ID
openwarp import .env
```

Exports contain plaintext. Keep them out of source control, shared terminal output, and build logs. Dotenv import is a parser for key/value text, not a shell interpreter; do not expect shell expansion or arbitrary dotenv dialects. Prefer JSON when a consumer needs an unambiguous structured representation. Sealed values are not available for readback.

`--base` leaves out your personal overrides and returns the environment's shared values. Use it in automation: an export that runs as whoever minted the token should not deploy that person's local stand-ins. [Kubernetes](KUBERNETES.md) uses this form for init containers.

### Child-process injection

```bash
openwarp run -- ./your-app
openwarp run -- sh -c 'printf "%s\n" "$EXAMPLE_GREETING"'
```

The CLI sets fetched values in the child's environment and propagates its exit status. The `--` separates OpenWarp arguments from the child command. Shell operators require an explicit shell, as in the second example. Do not run untrusted programs with production secrets.

## Encrypted files

File commands run offline and do not load saved credentials or contact an instance. They encrypt an entire file in an OpenWarp JSON envelope, not the SOPS file format. File names and sizes remain visible; JSON keys inside the input do not.

```bash
openwarp file keygen --out identity.json
openwarp file encrypt settings.json --recipient PUBLIC_KEY --out settings.ow.json
openwarp file decrypt settings.ow.json --identity identity.json --out settings.local.json
openwarp file rekey settings.ow.json --identity identity.json --recipient NEW_PUBLIC_KEY --out settings.rekeyed.json
```

The identity file contains `public_key` and `private_key`. Keep it outside version control and back it up separately from encrypted files. Encryption accepts up to 16 MiB and 1-32 distinct X25519 recipients; repeat `--recipient` for additional recipients. Any listed recipient can decrypt. The envelope authenticates the payload and recipient metadata.

Every output must be a new path. Existing files and symlinks are refused; Unix output permissions are 0600. Decrypt and rekey authenticate the source before creating output. Rekey replaces the recipients and preserves the encrypted payload. It does not revoke an old copy: anyone who saved the previous envelope or data key can still decrypt that copy.

## Secret references

Use a reference to select a secret by environment ID, path and key. A root reference is `ow://ENV_ID/KEY`; a nested reference is `ow://ENV_ID/team/db/KEY` for the path `/team/db/`. Percent-encode spaces and other special characters in individual path segments. References never select a different server; the host and token come from normal CLI configuration.

A UTF-8 template can contain `{{ow://ENV_ID/KEY}}` placeholders:

```bash
openwarp inject --input app.template --out app.local.conf
```

Without `--out`, `inject` writes plaintext to standard output. All references resolve before any output is written. Returned values are inserted literally and are not expanded as further references. Output files follow the new-only and Unix 0600 rules above. Templates are literal substitution, not JSON, shell or YAML escaping; quote values for the destination format yourself.

For process injection, put explicit environment-variable bindings in a JSON file:

```json
{"DATABASE_URL":"ow://ENV_ID/services/db/DATABASE_URL"}
```

```bash
openwarp run --env ENV_ID --refs-file bindings.json -- ./your-app
```

With `--refs-file`, OpenWarp injects only the listed bindings rather than exporting the whole environment. All bindings must resolve before the child starts. Command arguments remain literal. The child still inherits the calling process's ordinary environment; this is not a sandbox. OpenWarp removes inherited `OPENWARP_TOKEN` and `OPENWARP_PRIVKEY` in this mode, unless an explicit binding supplies that name. Without `--refs-file`, `run` retains its whole-environment export behavior.

References use current server authorization and resolve afresh on each CLI invocation. Sealed or unreadable targets fail. For an E2E or delegated environment, pass `--identity identity.json` containing the public/private key pair that holds a wrapped environment-key grant. Decryption happens in the CLI. An unrelated offline file identity does not grant access to an environment. These commands do not provide biometric authorization.

## End-to-end environments

E2E operations use separate endpoints and perform encryption/decryption locally. Do not substitute ordinary `set`, `get`, or `run` for these commands.

```bash
openwarp e2e-create --app APP_ID --name Private
```

Record the returned environment ID. The create flow generates an environment key locally and wraps it for your account's public key. To read, write, or grant access, supply your recovery kit through `OPENWARP_PRIVKEY` using your secret-management mechanism, rather than putting it literally in a command:

```bash
openwarp e2e-put --env E2E_ENV_ID --key EXAMPLE_SECRET --value dummy-value
openwarp e2e-get --env E2E_ENV_ID
openwarp e2e-grant --env E2E_ENV_ID --email colleague@example.invalid
```

These commands also accept `--privkey`, but that exposes the key as an argument. The recipient must be an eligible account whose public key can be resolved and must have the relevant environment access. Granting a wrapped key and granting workspace access are distinct operations. Protect your original recovery kit; changing the private key does not decrypt old grants.

## SSH certificates

These commands sign your existing OpenSSH public key with a workspace SSH CA. Only the public key is sent; the private key stays on your machine. The certificate is valid for one principal, which must be granted to your role on that CA.

```bash
openwarp ssh cert --ca CA_ID --principal deploy --print
openwarp ssh cert --ca CA_ID --principal deploy --key ~/.ssh/id_ed25519 --ttl 30m
openwarp ssh login --ca CA_ID --principal deploy -- deploy@host.internal
openwarp ssh config --ca CA_ID --principal deploy
openwarp ssh host-cert --ca CA_ID --hostname db-1.internal --key /etc/ssh/ssh_host_ed25519_key
```

`cert` signs and writes the certificate beside your key as `<key>-cert.pub`, which OpenSSH loads automatically, or prints it with `--print`. `login` mints a certificate and then runs `ssh -i <key> -o IdentitiesOnly=yes`, so the host sees the certificate rather than an agent key. `config` prints an `~/.ssh/config` block that mints a certificate before each matching connection. `host-cert` signs a server's host key for a hostname an admin registered, defaulting to 30 days and capped at 90; sshd picks the result up from `<key>-cert.pub` next to its host key.

A certificate for `root`, or one issued under a bare `*` grant, needs a second factor. The server answers 428 and these commands prompt for the emailed code, and for the authenticator code when the account has TOTP, then retry once. A machine token cannot step up and is refused instead.

The CA is selected with `--ca` or `OPENWARP_SSH_CA`. `--key` defaults to `~/.ssh/id_ed25519`. `--ttl` accepts `90s`, `15m`, `2h`, `1d` or a number of seconds, and the workspace's grant can cap it lower. `--quiet` suppresses the summary, which is what the `Match exec` snippet uses.

A certificate is a short-lived credential, not a stored key. Revoking one takes effect on a host only after that host refreshes its `RevokedKeys` file; otherwise it stops working when it expires.

## Completion

```bash
openwarp completion bash
openwarp completion zsh
openwarp completion fish
openwarp completion powershell
```

The command prints completion definitions. Install the output according to your shell's completion conventions; it does not configure your shell automatically.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `OPENWARP_HOST` | Instance URL for the top-level host option |
| `OPENWARP_TOKEN` | Token for the top-level token option |
| `OPENWARP_CONFIG` | User configuration path |
| `OPENWARP_NO_KEYRING` | `1` disables credential-store use |
| `OPENWARP_PRIVKEY` | Recovery kit for E2E read/write/grant operations |

[Security model](SECURITY.md) · [Documentation index](README.md)
