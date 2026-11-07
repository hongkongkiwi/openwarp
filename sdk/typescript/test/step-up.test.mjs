import { test } from "node:test";
import assert from "node:assert/strict";
import { OpenWarpClient } from "../dist/index.js";

test("explicit step-up grant sets only its dedicated header and preserves bearer authentication", async () => {
  const calls = [];
  const client = new OpenWarpClient("https://example.invalid", "original-bearer", async (url, init) => {
    calls.push({ url, init });
    return Response.json({ ok: true });
  });
  await client.api("POST", ["incoming-webhooks", "hook", "reauthorize"], {}, undefined, "stepupg_safe-grant");
  assert.equal(calls.length, 1);
  const headers = new Headers(calls[0].init.headers);
  assert.equal(headers.get("X-OpenWarp-Step-Up"), "stepupg_safe-grant");
  assert.equal(headers.get("Authorization"), "Bearer original-bearer");
  assert.equal(calls[0].init.redirect, "error");
  assert.deepEqual(JSON.parse(calls[0].init.body), {});
  await client.api("GET", ["me"]);
  assert.equal(new Headers(calls[1].init.headers).has("X-OpenWarp-Step-Up"), false);
});

test("invalid explicit step-up grants are rejected before fetch", async () => {
  for (const grant of ["", "x\r\nAuthorization: forged", "x\0", "x\x1f", "x\x7f", "é", "x".repeat(513)]) {
    let calls = 0;
    const client = new OpenWarpClient("https://example.invalid", "original-bearer", async () => { calls++; return Response.json({}); });
    await assert.rejects(async () => client.api("POST", ["orgs"], {}, undefined, grant), TypeError, JSON.stringify(grant));
    assert.equal(calls, 0, "invalid grant must not reach transport");
  }
});
