import { test } from "node:test";
import assert from "node:assert/strict";
import { OpenWarpClient, OpenWarpError } from "../dist/index.js";

const secret = { id: "s/1", key: "TOKEN", value: "value", path: "/", type: "secret", comment: "", tags: "" };

test("encodes segments and sends bearer authentication", async () => {
  const client = new OpenWarpClient("https://example.invalid/prefix/", "token", async (url, init) => {
    assert.equal(url, "https://example.invalid/prefix/api/orgs/a%2Fb%20%3F%23%25/apps");
    assert.equal(init.headers.Authorization, "Bearer token");
    assert.equal(init.redirect, "error");
    return Response.json([]);
  });
  assert.deepEqual(await client.apps("a/b ?#%"), []);
});

test("setSecret sends default fields inside secrets wrapper", async () => {
  const client = new OpenWarpClient("https://example.invalid", "token", async (_, init) => {
    assert.equal(init.method, "PUT");
    assert.deepEqual(JSON.parse(init.body), { secrets: [{ key: "TOKEN", value: "value", path: "/", type: "secret", comment: "", tags: "" }] });
    return Response.json({ deployed: 1, sync_errors: [] });
  });
  assert.equal((await client.setSecret("env", "TOKEN", "value")).deployed, 1);
});

test("delete resolves case-insensitive key to encoded ID and accepts empty response", async () => {
  const calls = [];
  const client = new OpenWarpClient("https://example.invalid", "token", async (url, init) => {
    calls.push([url, init.method]);
    return init.method === "GET" ? Response.json({ secrets: [secret] }) : new Response(null, { status: 204 });
  });
  await client.deleteSecret("env", "token");
  assert.deepEqual(calls, [["https://example.invalid/api/envs/env/secrets", "GET"], ["https://example.invalid/api/secrets/s%2F1", "DELETE"]]);
});

test("missing deletion is a no-op and ambiguous deletion is rejected", async () => {
  const empty = new OpenWarpClient("https://example.invalid", "token", async () => Response.json({ secrets: [] }));
  assert.equal(await empty.getSecret("env", "missing"), undefined);
  await empty.deleteSecret("env", "missing");
  const ambiguous = new OpenWarpClient("https://example.invalid", "token", async () => Response.json({ secrets: [secret, { ...secret, path: "/other" }] }));
  await assert.rejects(ambiguous.deleteSecret("env", "token"), error => error instanceof OpenWarpError && error.status === 409);
});

test("API errors retain JSON or plain-text bodies", async () => {
  for (const body of [{ error: "denied" }, "denied"]) {
    const client = new OpenWarpClient("https://example.invalid", "token", async () => typeof body === "string" ? new Response(body, { status: 403 }) : Response.json(body, { status: 403 }));
    await assert.rejects(client.me(), error => error instanceof OpenWarpError && error.status === 403 && assert.deepEqual(error.body, body) === undefined);
  }
});

test("rejects URL dot segments", async () => {
  const client = new OpenWarpClient("https://example.invalid", "token", async () => { throw new Error("must not fetch"); });
  await assert.rejects(client.envs(".."), TypeError);
});
