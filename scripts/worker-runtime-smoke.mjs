#!/usr/bin/env node
// Uses an existing Worker bundle. Owns disposable, serial Wrangler fixtures.
// Run: node scripts/worker-runtime-smoke.mjs (WRANGLER may name a local executable).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { writeWorkerConfig } from './worker-config-smoke.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const maxBody = 8 * 1024 * 1024;
const publicOrigin = 'https://runtime.test.invalid';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let checks = 0, failures = 0;
const children = new Set();
const sockets = new Set();
const messages = [];
let slowMail = false, stalledAt = 0;
let temp;

async function check(name, run) {
  checks++;
  try { await run(); console.log(`PASS ${name}`); }
  catch (error) {
    failures++;
    // Never print HTTP payloads, cookies, bindings, or Wrangler logs.
    console.error(`FAIL ${name}: ${error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.name}`);
  }
}
function ensure(condition, message) { assert.ok(condition, message); }
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const s = net.createServer(); const port = await listen(s); await new Promise(resolve => s.close(resolve)); return port; }
async function call(base, route, { method = 'GET', json, headers = {}, timeout = 30000 } = {}) {
  const res = await fetch(base + route, {
    method, headers: { ...(json === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    body: json === undefined ? undefined : JSON.stringify(json), redirect: 'manual', signal: AbortSignal.timeout(timeout),
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = {}; }
  return { status: res.status, headers: res.headers, data };
}
async function stop(child) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) { children.delete(child); return; }
  try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
  await Promise.race([once(child, 'exit'), sleep(3000)]);
  if (child.exitCode === null && child.signalCode === null) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
    await once(child, 'exit');
  }
  children.delete(child);
}
async function fixture(label, extra, run) {
  const port = await freePort();
  const executable = process.env.WRANGLER || 'npx';
  const prefix = process.env.WRANGLER ? [] : ['--no-install', 'wrangler'];
  const bindings = {
    OPENWARP_ENV: 'production', OPENWARP_MASTER_KEY: crypto.randomBytes(32).toString('base64'),
    OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_PUBLIC_URL: publicOrigin,
    OPENWARP_ALLOW_PRIVATE_EGRESS: '1', OPENWARP_EMAIL_WEBHOOK: mailUrl, ...extra,
  };
  const args = [...prefix, 'dev', '--local', '--config', path.join(temp, 'config', 'wrangler.toml'),
    '--port', String(port), '--persist-to', path.join(temp, label)];
  for (const [key, value] of Object.entries(bindings)) args.push('--var', `${key}:${value}`);
  const child = spawn(executable, args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child);
  // Drain logs without retaining bindings or account material.
  child.stdout.resume(); child.stderr.resume();
  let spawnError; child.on('error', error => { spawnError = error; });
  try {
    let listening = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler exited before fixture became ready');
      listening = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1');
        socket.setTimeout(100);
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false));
        socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (listening) break;
      await sleep(100);
    }
    ensure(listening, 'Wrangler fixture did not open its listener');
    await run(`http://127.0.0.1:${port}`);
  } finally { await stop(child); }
}

// Leave a chunked body unfinished after crossing the limit. A 413 must arrive
// without EOF; checking status after end() would miss the unbounded-read defect.
async function streamingLimit(base) {
  await new Promise((resolve, reject) => {
    const req = http.request(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' } });
    const timer = setTimeout(() => {
      const error = new Error('no response before request EOF'); error.name = 'OversizedStreamDeadline';
      reject(error); req.destroy();
    }, 10000);
    req.on('error', error => { clearTimeout(timer); reject(error); });
    req.on('response', res => {
      clearTimeout(timer);
      res.resume();
      try { ensure(res.statusCode === 413, 'unfinished oversized stream must return HTTP 413'); resolve(); }
      catch (error) { reject(error); }
      finally { req.destroy(); }
    });
    void (async () => {
      try {
        for (let sent = 0; sent <= maxBody; sent += 64 * 1024) {
          const size = Math.min(64 * 1024, maxBody + 1 - sent);
          if (!req.write(Buffer.alloc(size, 0x20))) await once(req, 'drain');
        }
      } catch (error) { clearTimeout(timer); req.destroy(); reject(error); }
    })();
  });
}

const mail = http.createServer(async (req, res) => {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  try { messages.push(JSON.parse(raw)); } catch { messages.push({}); }
  if (slowMail) { stalledAt = performance.now(); return; }
  res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}');
});
mail.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
const mailPort = await listen(mail);
const mailUrl = `http://127.0.0.1:${mailPort}/mail`;

async function validRuntime(base) {
  await check('valid production fixture serves health', async () => {
    ensure((await call(base, '/health')).status === 200, 'valid production health must be HTTP 200');
  });
  await check('public internal namespace remains HTTP 404', async () => {
    for (const route of ['/__internal/rotation-tick', '/__internal/not-a-route']) {
      for (const method of ['GET', 'POST']) ensure((await call(base, route, { method })).status === 404, 'public internal paths must be HTTP 404');
    }
  });
  await check('streaming oversize is rejected before request EOF', () => streamingLimit(base));
  await check('exactly 8 MiB still reaches the shared handler', async () => {
    const prefix = '{"email":"absent@test.invalid","password":"not-a-password","padding":"';
    const json = prefix + 'x'.repeat(maxBody - Buffer.byteLength(prefix) - 2) + '"}';
    ensure(Buffer.byteLength(json) === maxBody, 'boundary fixture must be exactly 8 MiB');
    const res = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: json, signal: AbortSignal.timeout(15000) });
    await res.arrayBuffer();
    ensure(res.status === 401, 'an at-limit valid JSON request must reach login, not HTTP 413');
  });
  await check('HTTPS session cookies and pinned MCP Origin survive Worker conversion', async () => {
    const email = `runtime-${crypto.randomUUID()}@test.invalid`, password = crypto.randomUUID();
    const start = messages.length;
    const registered = await call(base, '/api/auth/register', { method: 'POST', json: { email, password } });
    ensure(registered.status === 200 && registered.data.verification_required === true, 'fixture signup must require email verification');
    let link;
    for (let i = 0; i < 80 && !link; i++) {
      const msg = messages.slice(start).find(message => message.to === email);
      link = String(msg?.text || '').match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
      if (!link) await sleep(100);
    }
    ensure(!!link, 'verification mail must reach the isolated sink');
    const url = new URL(link);
    ensure(url.origin === publicOrigin, 'verification URL must use pinned HTTPS public origin');
    const verified = await call(base, url.pathname + url.search);
    ensure([200, 302, 303].includes(verified.status), 'email verification must succeed');
    const login = await call(base, '/api/auth/login', { method: 'POST', json: { email, password } });
    const cookie = login.headers.get('set-cookie') || '';
    ensure(login.status === 200 && !!login.data.token, 'verified password login must issue a session');
    for (const attribute of [/;\s*Secure(?:;|$)/i, /;\s*HttpOnly(?:;|$)/i, /;\s*SameSite=Lax(?:;|$)/i]) ensure(attribute.test(cookie), 'session cookie must retain Secure, HttpOnly, and SameSite=Lax');
    const headers = { cookie: cookie.split(';')[0] };
    ensure((await call(base, '/api/me', { headers })).status === 200, 'cookie-only session must authenticate through Worker conversion');
    const json = { jsonrpc: '2.0', id: 1, method: 'ping' };
    for (const origin of [publicOrigin, null]) {
      const response = await call(base, '/mcp', { method: 'POST', json, headers: { ...headers, ...(origin ? { origin } : {}) } });
      ensure(response.status === 200 && !!response.data.result, 'pinned or absent MCP Origin must accept an authenticated request');
    }
    const denied = await call(base, '/mcp', { method: 'POST', json, headers: { ...headers, origin: 'https://other.test.invalid' } });
    ensure(denied.status === 403, 'foreign MCP Origin must be HTTP 403 even with a valid session');
  });
}

try {
  await fs.access(path.join(root, 'crates/server/build/worker/shim.mjs'));
  temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-runtime-smoke-'));
  await fs.mkdir(path.join(temp, 'config'));
  await writeWorkerConfig(path.join(temp, 'config'));
  await check('valid runtime fixture lifecycle', () => fixture('valid', {}, validRuntime));
  for (const [label, vars] of [
    ['missing-public-url', { OPENWARP_PUBLIC_URL: '' }],
    ['http-public-url', { OPENWARP_PUBLIC_URL: 'http://runtime.test.invalid' }],
    ['unknown-auth-provider', { OPENWARP_AUTH_PROVIDERS: 'not-a-provider' }],
    ['unconfigured-auth-provider', { OPENWARP_AUTH_PROVIDERS: 'google', OPENWARP_GOOGLE_CLIENT_ID: '', OPENWARP_GOOGLE_CLIENT_SECRET: '' }],
  ]) {
    await check(`invalid production configuration rejected: ${label}`, () => fixture(label, vars, async base => {
      // A dead process, refused socket, or timeout is a harness failure, not rejection evidence.
      for (const route of ['/health', '/api/auth/providers']) {
        const response = await call(base, route, { timeout: 15000 });
        ensure(response.status >= 500 && response.status <= 599, 'invalid configuration must return a server error, not serve the application');
        ensure(!response.headers.has('set-cookie'), 'invalid configuration must never issue a session cookie');
      }
    }));
  }
  await check('explicit outbound 15-second mail deadline expires before the smoke watchdog', async () => {
    slowMail = true; stalledAt = 0;
    try {
      await fixture('slow-mail', {}, async base => {
        ensure((await call(base, '/health')).status === 200, 'timeout fixture must first pass health');
        const before = messages.length;
        const response = await call(base, '/api/auth/register', { method: 'POST', timeout: 23000,
          json: { email: `deadline-${crypto.randomUUID()}@test.invalid`, password: crypto.randomUUID() } });
        ensure(messages.length > before && stalledAt > 0, 'timeout probe must actually reach the deliberately stalled mail server');
        ensure(performance.now() - stalledAt >= 12000, 'the stalled request must honor its 15-second budget rather than fail immediately');
        ensure(response.status === 200 && response.data.verification_required === true, 'mail timeout must release signup without issuing a session');
        ensure(!response.data.token && !response.headers.has('set-cookie'), 'failed delivery must not bypass email verification');
        ensure((await call(base, '/health')).status === 200, 'Worker must remain usable after outbound timeout');
      });
    } finally { slowMail = false; }
  });
} catch (error) {
  failures++;
  console.error(`FAIL runtime harness setup: ${error.code || error.name}`);
} finally {
  for (const child of children) await stop(child);
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => mail.close(resolve));
  if (temp) await fs.rm(temp, { recursive: true, force: true });
}
console.log(`${checks} runtime checks, ${failures} failures`);
process.exitCode = failures ? 1 : 0;
