// Integration test for the TypeScript SDK against a real server binary.
// Run: node --test sdks/typescript/sdk.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { OpenWarp, OpenWarpError } from "./openwarp.ts";

const BIN = process.env.OPENWARP_BIN
  ?? fileURLToPath(new URL("../../target/debug/openwarp-server", import.meta.url));

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function startServer(): Promise<{ base: string; child: ChildProcess; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), "openwarp-sdk-ts-"));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const env = { ...process.env, DATABASE_URL: `sqlite://${dir}/sdk.db`, ADDR: `127.0.0.1:${port}`, OPENWARP_PUBLIC_URL: base, TOKIO_WORKER_THREADS: "2" };
  delete env.OPENWARP_MASTER_KEY;
  delete env.REDIS_URL;
  const child = spawn(BIN, [], { env, stdio: "ignore" });
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) return { base, child, dir };
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill("SIGKILL");
  throw new Error(`server did not start at ${base}`);
}

test("TypeScript SDK round trip against a live server", async () => {
  const { base, child, dir } = await startServer();
  try {
    const client = new OpenWarp({ host: base });
    const reg = await client.register("sdk-ts@test.invalid", "sdk-password-1");
    assert.ok(reg.token, "register returns a session");
    client.token = reg.token;

    assert.equal((await client.me()).email, "sdk-ts@test.invalid");
    const providers = await client.providers();
    assert.equal(providers.password, true);
    assert.ok(providers.signups === "open" || providers.signups === "invite");

    const orgs = await client.listOrgs();
    assert.equal(orgs.length, 1);
    const org = orgs[0].id;

    const app = await client.createApp(org, "sdk-app");
    const envs = await client.listEnvs(app.id);
    assert.equal(envs.length, 3);
    const [dev, prod] = envs;

    const deployed = await client.deploySecrets(dev.id, [
      { key: "API_KEY", value: "v1" },
      { key: "DB_URL", value: "postgres://localhost/app" },
    ]);
    assert.equal(deployed.deployed, 2);

    const listed = await client.listSecrets(dev.id);
    const apiKey = listed.secrets.find((s) => s.key === "API_KEY");
    assert.ok(apiKey, "deployed key is listed");
    assert.equal(apiKey.value, "v1");
    assert.equal((await client.exportEnv(dev.id)).text.includes("API_KEY=v1"), true);

    const history = await client.secretHistory(apiKey.id);
    assert.equal(history[0].version, 1);

    await client.deploySecrets(dev.id, [{ key: "API_KEY", value: "v2" }]);
    await client.restoreSecret(apiKey.id, 1);
    const restored = await client.listSecrets(dev.id);
    assert.equal(restored.secrets.find((s) => s.key === "API_KEY")?.value, "v1");

    const created = await client.createToken(app.id, "ci", dev.id);
    const scoped = new OpenWarp({ host: base, token: created.token });
    assert.equal((await scoped.listSecrets(dev.id)).secrets.length > 0, true);
    await assert.rejects(() => scoped.listSecrets(prod.id), (err: unknown) => err instanceof OpenWarpError && err.status === 403);
    await client.revokeToken(created.id);

    const found = await client.search("API");
    assert.ok(found.results.some((r) => r.key === "API_KEY"), "search finds the key");

    const lease = await client.createLease(dev.id, { name: "ts-lease" });
    assert.ok(lease.value, "lease carries a value");
    assert.ok((await client.listLeases(dev.id)).some((l) => l.id === lease.id));
    await client.revokeLease(lease.id);

    const rotation = await client.createRotation(dev.id, "API_KEY", 60);
    assert.ok(rotation.id);
    await client.deleteRotation(rotation.id);

    await client.deleteSecret(listed.secrets.find((s) => s.key === "DB_URL")!.id);
    assert.equal((await client.listSecrets(dev.id)).secrets.some((s) => s.key === "DB_URL"), false);

    await assert.rejects(() => client.deploySecrets("missing-env", [{ key: "X", value: "y" }]), (err: unknown) => err instanceof OpenWarpError && err.status === 404);
  } finally {
    child.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
});
