import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { OpenWarpClient, OpenWarpError } from "../dist/index.js";

test("management api rejects base URL query and fragment delimiters before fetch", async () => {
  for (const suffix of ["?", "#", "?#", "?scope=admin", "#capture", "?scope=admin#capture"]) {
    let calls = 0;
    const fetchImpl = async () => { calls++; return Response.json({}); };
    await assert.rejects(async () => {
      const client = new OpenWarpClient(`https://example.invalid/prefix/${suffix}`, "private-test-token", fetchImpl);
      await client.api("POST", ["orgs"], { name: "private" });
    }, TypeError, suffix);
    assert.equal(calls, 0, `invalid base ${suffix} must not send a credential-bearing request`);
  }
});

const unsafe = [".", "..", "%2e", "%2E%2e", ".%2e", "%252e%252e", "a/../b", "a%2f..%2fb", "a%252f%252e%252e%252fb", "bad%", "%GG", "back\\slash", "bad\n", "bad\0", "bad\x7f", "https://example.invalid/api/me", "//example.invalid/api/me"];

test("management api encodes segments and query independently", async () => {
  const client = new OpenWarpClient("https://example.invalid/prefix/", "test-token", async (url, init) => {
    const parsed = new URL(url);
    assert.equal(parsed.pathname, "/prefix/api/orgs/a%2Fb%20%3F%23%E9%9B%AA/audit");
    assert.deepEqual([...parsed.searchParams], [["search", "a&b=雪 +/?#"], ["limit", "2"]]);
    assert.equal(init.headers.Authorization, "Bearer test-token");
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "error");
    return Response.json({ ok: true });
  });
  assert.deepEqual(await client.api("GET", ["orgs", "a/b ?#雪", "audit"], undefined, { search: "a&b=雪 +/?#", limit: "2" }), { ok: true });
});

test("management api supports all verbs and empty success", async () => {
  for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]) {
    const body = ["POST", "PUT", "PATCH"].includes(method) ? { name: "雪" } : undefined;
    const client = new OpenWarpClient("https://example.invalid", "test-token", async (url, init) => {
      assert.equal(url, "https://example.invalid/api/orgs/o/settings");
      assert.equal(init.method, method);
      if (body) assert.deepEqual(JSON.parse(init.body), body);
      else assert.equal(init.body, undefined);
      return new Response(null, { status: 204 });
    });
    assert.equal(await client.api(method, ["orgs", "o", "settings"], body), undefined);
  }
});

test("management api rejects unsafe segments and unsupported verbs before fetch", async () => {
  let calls = 0;
  const client = new OpenWarpClient("https://example.invalid", "test-token", async () => { calls++; return Response.json({}); });
  assert.equal(typeof client.api, "function", "public generic api must exist before testing input rejection");
  for (const segment of unsafe) await assert.rejects(async () => client.api("GET", ["orgs", segment]));
  for (const method of ["TRACE", "CONNECT", "BREW", "GET\r\nX-Test: yes"]) await assert.rejects(async () => client.api(method, ["me"]));
  assert.equal(calls, 0);
});

test("management api preserves HTTP status and response body", async () => {
  for (const status of [400, 401, 403, 404, 409, 429, 500, 503]) {
    for (const body of [{ error: "denied" }, "provider unavailable"]) {
      const client = new OpenWarpClient("https://example.invalid", "test-token", async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status }));
      await assert.rejects(client.api("GET", ["orgs"]), e => e instanceof OpenWarpError && e.status === status && assert.deepEqual(e.body, body) === undefined);
    }
  }
});

async function listen(handler) {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

async function close(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

test("management api never follows same-origin or cross-origin redirects", async () => {
  const captured = [];
  const target = await listen((req, res) => { captured.push(req.headers); res.end("{}"); });
  let sourceCalls = 0;
  let location = target.base + "/capture";
  const source = await listen((req, res) => {
    sourceCalls++;
    if (req.url === "/capture") { captured.push(req.headers); res.end("{}"); return; }
    res.writeHead(307, { Location: location }); res.end();
  });
  try {
    const client = new OpenWarpClient(source.base, "private-test-token");
    for (const destination of [target.base + "/capture", source.base + "/capture"]) {
      location = destination;
      await assert.rejects(client.api("POST", ["orgs"], { name: "private" }));
    }
    assert.equal(sourceCalls, 2);
    assert.deepEqual(captured, []);
  } finally { await close(source.server); await close(target.server); }
});
