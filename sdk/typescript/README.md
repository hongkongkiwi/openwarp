# OpenWarp TypeScript SDK

ES2022 ESM client with no runtime dependencies. Requires Node.js 18+ or a runtime with Fetch, URL, and Response. The base URL is the server origin with an optional deployment prefix, without `/api`, credentials, query, or fragment. Use HTTPS in production.

```ts
import { OpenWarpClient, OpenWarpError } from "@openwarp/sdk";

const client = new OpenWarpClient("https://openwarp.example.invalid", "your-token");
await client.setSecret("env-id", "DATABASE_URL", "postgres://example");
const secret = await client.getSecret("env-id", "DATABASE_URL");
const lease = await client.createLease("env-id", { name: "worker", ttl_secs: 3600 });
```

Methods: `me()`, `orgs()`, `apps(org)`, `envs(app)`, `secrets(env)`, `getSecret(env,key)`, `setSecret(env,key,value,path="/",type="secret",comment="")`, `deleteSecret(env,key)`, `export(env)`, `leases(env)`, `createLease(env,input={})`, `audit(org)`.

`secrets` unwraps the response array. `export` returns `{text,secrets}`. `setSecret` returns the deployment result, including sync errors. Tags are sent as an empty string, which clears existing tags when updating. Lease input accepts `name`, `ttl_secs`, `type`, and `config`; PostgreSQL creation can return `username` and `password` instead of `value`.

Key lookup is case-insensitive. Missing keys return `undefined`; deleting a missing key does nothing. A key present at multiple paths raises a local `OpenWarpError` with status 409. Use `secrets` to inspect paths. API non-success responses throw `OpenWarpError(status,message,body)`; transport and JSON decoding errors propagate unchanged. Error bodies can contain sensitive values, so do not log them indiscriminately. Redirects and dot path segments are rejected.

The optional third constructor argument is a Fetch-compatible function for testing or a custom transport.

## Local checks

With the declared TypeScript development dependency already available, `npm run build` emits JavaScript and declarations into `dist`; `npm test` builds and runs six offline mock-Fetch tests. No dependencies were installed, and neither command was run when creating this scaffold. Compilation and test results are unverified.
