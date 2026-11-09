#!/usr/bin/env node
// Runs serial local fixtures against an existing Worker bundle, without rebuilding.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeWorkerConfig } from './worker-config-smoke.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const children = new Set(), sockets = new Set();
let temp, config, providerUrl, mode = 'reject', arrived = 0, checks = 0, failures = 0;
async function check(name, run) {
  checks++;
  try { await run(); console.log(`PASS ${name}`); }
  catch (error) {
    failures++;
    // Request bodies, credentials, response payloads and Wrangler logs stay private.
    console.error(`FAIL ${name}: ${error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.name}`);
  }
}
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
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
  const vars = {
    OPENWARP_ENV: 'production', OPENWARP_MASTER_KEY: crypto.randomBytes(32).toString('base64'),
    OPENWARP_PUBLIC_URL: 'https://kms-review.test.invalid', OPENWARP_AUTH_PROVIDERS: 'workos',
    OPENWARP_WORKOS_CLIENT_ID: 'dummy-client', OPENWARP_WORKOS_CLIENT_SECRET: 'dummy-client-secret',
    OPENWARP_WORKOS_API: providerUrl, OPENWARP_ALLOW_PRIVATE_EGRESS: '1', ...extra,
  };
  const args = [...(process.env.WRANGLER ? [] : ['--no-install', 'wrangler']), 'dev', '--local',
    '--config', config, '--port', String(port), '--persist-to', path.join(temp, label)];
  for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
  const child = spawn(process.env.WRANGLER || 'npx', args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child); child.stdout.resume(); child.stderr.resume();
  let spawnError; child.on('error', error => { spawnError = error; });
  try {
    let ready = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler exited before listener readiness');
      ready = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1'); socket.setTimeout(100);
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false)); socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (ready) break;
      await sleep(100);
    }
    ensure(ready, 'Wrangler fixture did not open its listener');
    await run(`http://127.0.0.1:${port}`);
  } finally { await stop(child); }
}
async function call(base, route, headers = {}, timeout = 15000) {
  const response = await fetch(base + route, { headers, redirect: 'manual', signal: AbortSignal.timeout(timeout) });
  await response.arrayBuffer();
  return response;
}
const provider = http.createServer(async (request, response) => {
  let size = 0;
  for await (const chunk of request) size += chunk.length;
  if (request.method !== 'POST' || request.url !== '/user_management/authenticate' || size === 0) {
    response.writeHead(404); response.end(); return;
  }
  arrived = performance.now();
  if (mode === 'headers') return;
  if (mode === 'body') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.write('{"user":');
    return;
  }
  response.writeHead(400, { 'content-type': 'application/json' }); response.end('{"error":"dummy rejection"}');
});
provider.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
async function callback(base, timeout = 15000) {
  const start = await call(base, '/api/auth/social/workos/start');
  ensure(start.status === 307, 'configured WorkOS flow must issue an authorization redirect');
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const cookie = (start.headers.get('set-cookie') || '').split(';')[0];
  ensure(!!state && cookie.startsWith('ow_social_'), 'real authorization flow must issue state and browser proof');
  return call(base, `/api/auth/social/workos/callback?state=${encodeURIComponent(state)}&code=dummy-code`, { cookie }, timeout);
}
try {
  await fs.access(path.join(root, 'crates/server/build/worker/shim.mjs'));
  temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-kms-review-'));
  const configDir = path.join(temp, 'config'); await fs.mkdir(configDir); config = await writeWorkerConfig(configDir);
  providerUrl = `http://127.0.0.1:${await listen(provider)}`;
  await check('mixed-case production with a valid HTTPS origin remains healthy', () => fixture('mixed-valid', { OPENWARP_ENV: 'Production' }, async base => {
    ensure((await call(base, '/health')).status === 200, 'valid mixed-case production fixture must serve health');
  }));
  for (const [label, env, origin] of [
    ['lowercase-missing-origin', 'production', ''],
    ['mixed-case-missing-origin', 'Production', ''],
    ['mixed-case-http-origin', 'PrOdUcTiOn', 'http://kms-review.test.invalid'],
  ]) {
    await check(`production rejects invalid origin: ${label}`, () => fixture(label, { OPENWARP_ENV: env, OPENWARP_PUBLIC_URL: origin }, async base => {
      const response = await call(base, '/health');
      ensure(response.status >= 500 && response.status <= 599, 'invalid production origin must return an HTTP server error, not serve health');
      ensure(!response.headers.has('set-cookie'), 'invalid production origin must not issue a session');
    }));
  }
  await fixture('provider-deadlines', {}, async base => {
    await check('valid provider fixture serves health and handles an immediate provider rejection', async () => {
      ensure((await call(base, '/health')).status === 200, 'provider fixture must first pass health');
      mode = 'reject'; arrived = 0;
      const response = await callback(base);
      ensure(arrived > 0, 'callback must reach the real local provider fixture');
      ensure(response.status === 400, 'provider rejection must fail sign-in');
      ensure(!/ow_session=/.test(response.headers.get('set-cookie') || ''), 'provider rejection must not issue a session');
    });
    for (const phase of ['headers', 'body']) {
      await check(`provider POST has a 30-second deadline while awaiting ${phase}`, async () => {
        mode = phase; arrived = 0;
        let response;
        try { response = await callback(base, 38000); }
        catch (error) {
          ensure(arrived > 0, 'deadline probe must first reach the local provider fixture');
          if (error.name === 'TimeoutError' || error.name === 'AbortError') {
            assert.fail('provider POST must finish within its 30-second deadline; the 38-second smoke watchdog expired after provider arrival');
          }
          throw error;
        }
        ensure(arrived > 0, 'deadline probe must first reach the local provider fixture');
        const elapsed = performance.now() - arrived;
        ensure(elapsed >= 25000 && elapsed < 36000, 'stalled provider POST must honor its 30-second deadline');
        ensure(response.status === 400, 'provider timeout must fail sign-in with an HTTP response');
        ensure(!/ow_session=/.test(response.headers.get('set-cookie') || ''), 'provider timeout must not issue a session');
        ensure((await call(base, '/health')).status === 200, 'Worker must remain usable after provider timeout');
      });
      for (const socket of sockets) socket.destroy();
    }
  });
} catch (error) {
  failures++;
  console.error(`FAIL Worker review harness setup: ${error.code || error.name}`);
} finally {
  for (const child of children) await stop(child);
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => provider.close(resolve));
  if (temp) await fs.rm(temp, { recursive: true, force: true });
}
console.log(`${checks} Worker review checks, ${failures} failures`);
process.exitCode = failures ? 1 : 0;
