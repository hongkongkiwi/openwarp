# OpenWarp TypeScript SDK

No runtime dependencies. Uses global `fetch`; runs on Node 22+ (native
TypeScript type stripping) or any bundler that understands `.ts`.

```ts
import { OpenWarp } from "./openwarp.ts";

const ow = new OpenWarp({ host: "https://secrets.example.com" });
const session = await ow.login("you@company.com", "password");
ow.token = session.token;

const [org] = await ow.listOrgs();
const app = await ow.createApp(org.id, "billing-api");
const envs = await ow.listEnvs(app.id);
await ow.deploySecrets(envs[0].id, [{ key: "API_KEY", value: "v1" }]);
console.log((await ow.exportEnv(envs[0].id)).text);
```

The contract is [`../../../openapi.json`](../../../openapi.json). `OpenWarpError`
carries `status` and the parsed body. Environment ids, tokens and org ids are
all opaque strings; pass them through unchanged.

## Test

```bash
cargo build -p openwarp-server
OPENWARP_BIN=target/debug/openwarp-server node --test sdk/contract/typescript/sdk.test.ts
```

The test starts a private server on a loopback port with a temporary SQLite
database, exercises authentication, secrets, tokens, scoping, leases, rotations
and search, and then removes everything.
