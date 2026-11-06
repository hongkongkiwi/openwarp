# Getting started

This walkthrough runs OpenWarp locally, creates a standard server-encrypted environment, and passes a secret to a child process. Use dummy values while learning the workflow.

## Prerequisites

- Git and a Rust toolchain with Cargo.
- A browser.
- A native build toolchain for your operating system.

Node.js is needed for JavaScript contributor tests, not for running the Rust server. The local walkthrough uses SQLite and does not require Redis or PostgreSQL.

## Start a local instance

```bash
git clone https://github.com/hongkongkiwi/openwarp.git
cd openwarp
DATABASE_URL=sqlite://openwarp.db ADDR=127.0.0.1:8080 \
  cargo run -p openwarp-server
```

Leave that terminal running. Open [http://127.0.0.1:8080](http://127.0.0.1:8080) and register with an email address and a password of at least eight characters. On an instance with email verification enabled, complete verification before signing in.

Save the recovery kit in a private offline location or a secure password manager. It contains your private key. Do not paste it into an issue or commit it to the repository. The first account is the instance owner.

This command binds only to loopback. Without an external master key, development mode generates a key and stores it in the database. Do not treat this as a production deployment.

## Create an application and secret

1. Select your workspace in the console. API routes call workspaces organisations.
2. Open Apps and create an application, such as `Example service`.
3. Open its Development environment. New applications include Development, Staging, and Production.
4. Add a secret named `EXAMPLE_GREETING` with value `hello-openwarp` and path `/`.
5. Select Deploy changes to persist the staged draft.

Console drafts are not the same as deployed secrets. Other clients see the saved values after deployment. Direct CLI/API writes and imports have their own immediate persistence behavior.

## Install and authenticate the CLI

In another terminal, from the repository root:

```bash
cargo install --path crates/cli
openwarp --help
openwarp login
```

`login` uses browser OAuth with PKCE and a temporary loopback callback. Sign in and approve access. For a remote instance, put `--host` before the command:

```bash
openwarp --host "$OPENWARP_HOST" login
```

Set `OPENWARP_HOST` to your actual instance origin first. See the [CLI reference](CLI.md) for service-token and machine-identity login.

## Discover IDs and set project defaults

```bash
openwarp orgs
openwarp apps --org ORG_ID
openwarp envs --app APP_ID
openwarp init --app APP_ID --env ENV_ID
```

Replace each uppercase placeholder with the corresponding returned ID. Use the Development environment's ID, not its display name. Run `init` from the application directory where you will use OpenWarp. It writes `.openwarp.json` in that directory with host, application, and environment defaults.

## Read and inject the secret

```bash
openwarp secrets
openwarp get EXAMPLE_GREETING
openwarp run -- sh -c 'printf "%s\n" "$EXAMPLE_GREETING"'
```

The first command lists secrets with values redacted. The second prints the selected value. The final POSIX-shell example should print `hello-openwarp` from the child process's environment. On a system without `sh`, replace it with your application's executable.

Use `openwarp run -- ./your-app` for your own process. The process can read and disclose every value injected into it; use a suitably scoped identity.

## Import and export

```bash
openwarp import .env
openwarp export --format json
```

Import writes secrets to the selected environment. Review the target and input before importing. Export prints plaintext, so do not run it in shared logs or redirect it into a tracked file. See [CLI limitations](CLI.md#paths-and-secret-names) before using duplicate names in different paths or multiline values with dotenv-based consumers.

## Where to go next

| Goal | Guide |
| --- | --- |
| Invite colleagues and review drafts | [Console](CONSOLE.md) |
| Use CI credentials or E2E commands | [CLI](CLI.md) |
| Push secrets to a provider | [Integrations](INTEGRATIONS.md) |
| Deploy with HTTPS and backups | [Deployment](DEPLOY.md) |
| Understand key custody | [Security](SECURITY.md) |

[Documentation index](README.md)
