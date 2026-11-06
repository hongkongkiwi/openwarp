import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTcpServer } from "node:net";
import { OpenWarpClient } from "../dist/index.js";

const binary = process.env.OPENWARP_BIN || "../../target/debug/openwarp-server";

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createTcpServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function mailInbox() {
  const messages = [];
  const waiters = [];
  const server = createServer((req, res) => {
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
      } catch {
        // A malformed provider payload is a test failure only if no link arrives.
      }
      res.writeHead(204).end();
    });
  });
  return {
    server,
    next(timeoutMs = 10000) {
      if (messages.length) return Promise.resolve(messages.shift());
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("verification mail did not arrive")), timeoutMs);
        waiters.push(text => { clearTimeout(timer); resolve(text); });
      });
    },
  };
}

function verificationPath(text) {
  const marker = "/api/auth/verify?token=";
  const start = text.indexOf(marker);
  assert.notEqual(start, -1, `verification link missing from mail: ${text}`);
  const rest = text.slice(start + marker.length);
  const end = rest.search(/[\s"'<>]/);
  return marker + (end === -1 ? rest : rest.slice(0, end));
}

async function startServer(t) {
  if (!existsSync(binary)) {
    t.skip(`server binary not found at ${binary}; build it or set OPENWARP_BIN`);
    return undefined;
  }
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const dir = mkdtempSync(join(tmpdir(), "openwarp-ts-sdk-"));
  const inbox = mailInbox();
  await new Promise(resolve => inbox.server.listen(0, "127.0.0.1", resolve));
  const mailUrl = `http://127.0.0.1:${inbox.server.address().port}`;
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(OPENWARP_EMAIL_|OPENWARP_SMTP_|OPENWARP_RESEND_|OPENWARP_SENDGRID_|OPENWARP_MAILGUN_|OPENWARP_POSTMARK_|OPENWARP_CLOUDFLARE_EMAIL_|OPENWARP_MASTER_KEY|REDIS_URL|OPENWARP_ENV)/.test(key)) delete env[key];
  }
  Object.assign(env, {
    DATABASE_URL: `sqlite://${join(dir, "sdk.db")}`,
    ADDR: `127.0.0.1:${port}`,
    OPENWARP_PUBLIC_URL: base,
    OPENWARP_EMAIL_PROVIDER: "webhook",
    OPENWARP_EMAIL_WEBHOOK: mailUrl,
    OPENWARP_EMAIL_FROM: "no-reply@test.invalid",
    TOKIO_WORKER_THREADS: "2",
  });
  const child = spawn(binary, [], { env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", chunk => { output += chunk; });
  child.stderr.on("data", chunk => { output += chunk; });
  const cleanup = () => {
    child.kill("SIGKILL");
    inbox.server.close();
    rmSync(dir, { recursive: true, force: true });
  };
  t.after(cleanup);
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/health`);
      if (response.ok) return { base, inbox, output: () => output };
    } catch {
      // Server is still starting.
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`server did not become healthy: ${output}`);
}

async function jsonRequest(base, token, method, path, body) {
  const response = await fetch(base + path, {
    method,
    redirect: "error",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${path}: HTTP ${response.status} ${text}`);
  return text ? JSON.parse(text) : undefined;
}

test("live server round trip", { timeout: 45000 }, async t => {
  const server = await startServer(t);
  if (!server) return;
  const { base, inbox } = server;
  const email = "typescript-sdk@test.invalid";
  const password = "typescript-sdk-password";
  const registered = await jsonRequest(base, "", "POST", "/api/auth/register", { email, password });
  assert.equal(registered.verification_required, true);
  const mail = await inbox.next();
  const verified = await fetch(base + verificationPath(mail));
  assert.equal(verified.status, 200);
  const session = await jsonRequest(base, "", "POST", "/api/auth/login", { email, password });
  assert.ok(session.token);

  const client = new OpenWarpClient(base, session.token);
  const orgs = await client.orgs();
  assert.ok(orgs.some(org => org.id === registered.org_id));
  const app = await jsonRequest(base, session.token, "POST", `/api/orgs/${encodeURIComponent(registered.org_id)}/apps`, { name: "typescript-sdk" });
  const envs = await client.envs(app.id);
  assert.equal(envs.length, 3);
  const env = envs[0].id;

  const deployed = await client.setSecret(env, "SDK_TOKEN", "v1");
  assert.equal(deployed.deployed, 1);
  assert.equal((await client.getSecret(env, "sdk_token")).value, "v1");
  assert.equal((await client.export(env)).secrets.find(secret => secret.key === "SDK_TOKEN").value, "v1");
  await client.setSecret(env, "SDK_TOKEN", "v2");
  assert.equal((await client.getSecret(env, "SDK_TOKEN")).value, "v2");
  await client.deleteSecret(env, "SDK_TOKEN");
  assert.equal(await client.getSecret(env, "SDK_TOKEN"), undefined);
  assert.ok((await client.me()).id);
  assert.ok(Array.isArray(await client.audit(registered.org_id)));
});
