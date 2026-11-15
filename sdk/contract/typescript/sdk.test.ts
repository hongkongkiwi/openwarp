// Integration test for the TypeScript SDK against a real server binary.
// Run: node --test sdk/contract/typescript/sdk.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { fileURLToPath } from "node:url";
import { OpenWarp, OpenWarpError } from "./openwarp.ts";

const BIN = process.env.OPENWARP_BIN
  ?? fileURLToPath(new URL("../../../target/debug/openwarp-server", import.meta.url));

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

function mailInbox() {
  const messages: string[] = [];
  const waiters: ((text: string) => void)[] = [];
  const server = createHttpServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      try {
        const message = JSON.parse(body);
        if (typeof message.text === "string") {
          const waiter = waiters.shift();
          if (waiter) waiter(message.text);
          else messages.push(message.text);
        }
        res.writeHead(204).end();
      } catch {
        res.writeHead(400).end();
      }
    });
  });
  return {
    server,
    next(): Promise<string> {
      if (messages.length) return Promise.resolve(messages.shift()!);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("verification mail did not arrive")), 10_000);
        waiters.push(text => { clearTimeout(timer); resolve(text); });
      });
    },
  };
}

async function startServer() {
  const dir = mkdtempSync(join(tmpdir(), "openwarp-sdk-ts-"));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const inbox = mailInbox();
  await new Promise<void>(resolve => inbox.server.listen(0, "127.0.0.1", resolve));
  const address = inbox.server.address();
  assert.ok(address && typeof address === "object");
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(OPENWARP_EMAIL_|OPENWARP_SMTP_|OPENWARP_RESEND_|OPENWARP_SENDGRID_|OPENWARP_MAILGUN_|OPENWARP_POSTMARK_|OPENWARP_CLOUDFLARE_EMAIL_|OPENWARP_MASTER_KEY|REDIS_URL|OPENWARP_ENV)/.test(key)) delete env[key];
  }
  Object.assign(env, {
    DATABASE_URL: `sqlite://${dir}/sdk.db`,
    ADDR: `127.0.0.1:${port}`,
    OPENWARP_PUBLIC_URL: base,
    OPENWARP_EMAIL_PROVIDER: "webhook",
    OPENWARP_EMAIL_WEBHOOK: `http://127.0.0.1:${address.port}`,
    OPENWARP_EMAIL_FROM: "no-reply@test.invalid",
    TOKIO_WORKER_THREADS: "2",
  });
  const child = spawn(BIN, [], { env, stdio: "ignore" });
  const cleanup = () => {
    child.kill("SIGKILL");
    inbox.server.close();
    rmSync(dir, { recursive: true, force: true });
  };
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) return { base, inbox, cleanup };
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  cleanup();
  throw new Error("server did not start");
}

function verificationPath(text: string): string {
  const match = text.match(/\/api\/auth\/verify\?token=[^\s"'<>]+/);
  assert.ok(match, "verification link missing from mail");
  return match[0];
}

async function apiRequest(base: string, token: string, method: string, path: string, body?: unknown, stepUp?: string) {
  const response = await fetch(base + path, {
    method,
    redirect: "error",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(stepUp === undefined ? {} : { "X-OpenWarp-Step-Up": stepUp }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  assert.equal(response.status, 200, `${method} ${path} must succeed`);
  return response.json();
}

test("TypeScript SDK round trip against a live server", async () => {
  const { base, inbox, cleanup } = await startServer();
  try {
    const client = new OpenWarp({ host: base });
    const reg = await client.register("sdk-ts@test.invalid", "sdk-password-1");
    assert.equal(reg.verification_required, true);
    const link = base + verificationPath(await inbox.next());
    assert.equal((await fetch(link)).status, 200, "the verification link opens");
    const session = await client.login("sdk-ts@test.invalid", "sdk-password-1");
    assert.ok(session.token, "login after verification returns a session");
    client.token = session.token;

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
    await assert.rejects(() => client.exportEnv(dev.id), (err: unknown) => {
      assert.ok(err instanceof OpenWarpError);
      assert.equal(err.status, 428);
      const body = err.body as Record<string, unknown>;
      assert.equal(body.step_up_required, true);
      assert.equal(body.risk, "very_risky");
      assert.equal(body.email_required, true);
      assert.equal(body.totp_required, false);
      return true;
    });
    const challenge = await apiRequest(base, client.token, "POST", "/api/auth/step-up/start", { risk: "very_risky" });
    assert.ok(challenge.challenge);
    const emailCode = (await inbox.next()).match(/\b\d{6}\b/)?.[0];
    assert.ok(emailCode, "step-up verification code missing from mail");
    const grant = await apiRequest(base, client.token, "POST", "/api/auth/step-up/verify", {
      challenge: challenge.challenge,
      email_code: emailCode,
    });
    assert.ok(grant.token);
    const exported = await apiRequest(base, client.token, "GET", `/api/envs/${encodeURIComponent(dev.id)}/export`, undefined, grant.token);
    assert.equal(exported.text.includes("API_KEY=v1"), true);

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
    cleanup();
  }
});
