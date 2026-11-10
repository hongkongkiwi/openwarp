#!/usr/bin/env node
// Uses a prebuilt Worker bundle and disposable Wrangler state, never builds Rust.
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
const ensure = (value, message) => assert.ok(value, message);
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function call(base, route, { method = 'GET', cookie, json } = {}) {
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  let data; try { data = await response.json(); } catch { data = {}; }
  return { status: response.status, headers: response.headers, data };
}
const ok = (response, label) => { ensure(response.status === 200, `${label} must return HTTP 200 (got ${response.status})`); return response; };

// Node's global WebSocket cannot set Cookie. This HTTP upgrade client checks the
// RFC 6455 accept digest, handles split frames and answers server pings masked.
function connect(base, route = '/api/live', cookie, extra = {}) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const request = http.request(base + route, { headers: { connection: 'Upgrade', upgrade: 'websocket',
      'sec-websocket-version': '13', 'sec-websocket-key': key, ...(cookie ? { cookie } : {}), ...extra } });
    const timer = setTimeout(() => { request.destroy(); reject(new Error('WebSocket upgrade timed out')); }, 10000);
    request.on('error', error => { clearTimeout(timer); reject(error); });
    request.on('response', response => { clearTimeout(timer); response.resume(); resolve({ status: response.statusCode }); });
    request.on('upgrade', (response, socket, head) => {
      clearTimeout(timer);
      try {
        ensure(response.statusCode === 101, 'successful upgrade must be HTTP 101');
        ensure(response.headers['sec-websocket-accept'] === crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64'), 'upgrade must validate the WebSocket accept digest');
        const client = { status: 101, events: [], closed: false, error: null, close: () => socket.destroy() };
        let buffered = Buffer.alloc(0), fragments = [], fragmentOpcode = 0;
        const pong = bytes => {
          ensure(bytes.length <= 125, 'control payload must fit a WebSocket control frame');
          const mask = crypto.randomBytes(4), out = Buffer.alloc(6 + bytes.length);
          out[0] = 0x8a; out[1] = 0x80 | bytes.length; mask.copy(out, 2);
          for (let i = 0; i < bytes.length; i++) out[6 + i] = bytes[i] ^ mask[i % 4];
          socket.write(out);
        };
        const consume = chunk => {
          buffered = Buffer.concat([buffered, chunk]);
          while (buffered.length >= 2) {
            const fin = !!(buffered[0] & 0x80), opcode = buffered[0] & 15;
            ensure(!(buffered[1] & 0x80), 'server frames must not be masked');
            let length = buffered[1] & 127, offset = 2;
            if (length === 126) { if (buffered.length < 4) return; length = buffered.readUInt16BE(2); offset = 4; }
            if (length === 127) { if (buffered.length < 10) return; ensure(buffered.readBigUInt64BE(2) <= 1048576n, 'live frame must stay bounded'); length = Number(buffered.readBigUInt64BE(2)); offset = 10; }
            ensure(length <= 1048576, 'live frame must stay bounded');
            if (buffered.length < offset + length) return;
            const bytes = buffered.subarray(offset, offset + length); buffered = buffered.subarray(offset + length);
            if (opcode === 8) { client.closed = true; socket.end(); return; }
            if (opcode === 9) { pong(bytes); continue; }
            if (opcode === 10) continue;
            if (opcode !== 0) { ensure(!fragments.length, 'new message must not interrupt fragmented message'); fragmentOpcode = opcode; }
            fragments.push(bytes);
            ensure(fragments.reduce((size, part) => size + part.length, 0) <= 1048576, 'fragmented live message must stay bounded');
            if (fin) {
              ensure(fragmentOpcode === 1, 'live messages must be JSON text');
              client.events.push(JSON.parse(Buffer.concat(fragments).toString())); fragments = [];
            }
          }
        };
        socket.on('data', chunk => { try { consume(chunk); } catch (error) { client.error = error; socket.destroy(); } });
        socket.on('error', error => { client.error = error; });
        socket.on('close', () => { client.closed = true; });
        if (head.length) consume(head);
        resolve(client);
      } catch (error) { socket.destroy(); reject(error); }
    });
    request.end();
  });
}
async function event(client, predicate, label) {
  for (let i = 0; i < 200; i++) {
    if (client.error) throw client.error;
    const found = client.events.find(predicate);
    if (found) return found;
    ensure(!client.closed, `${label}: socket closed before matching event`);
    await sleep(50);
  }
  throw new Error(`${label}: no matching event before deadline`);
}
async function absent(client, predicate, label) {
  await sleep(1500);
  if (client.error) throw client.error;
  ensure(!client.events.some(predicate), label);
}

async function exercise(base, account) {
  const sockets = new Set();
  const open = async (cookie, route) => {
    const client = await connect(base, route, cookie);
    ensure(client.status === 101, `authenticated live endpoint must upgrade, not HTTP ${client.status}`);
    sockets.add(client);
    const hello = await event(client, value => value.type === 'hello', 'hello handshake');
    ensure(typeof hello.instance === 'string' && !!hello.instance, 'hello must identify the instance');
    return client;
  };
  try {
    for (const [cookie, extra] of [[undefined, {}], ['ow_session=invalid', {}], [undefined, { 'x-openwarp-live': '1', 'x-openwarp-live-authorized': 'true', 'x-openwarp-user': 'owner' }]]) {
      const denied = await connect(base, '/api/live', cookie, extra);
      if (denied.close) { denied.close(); }
      ensure(denied.status === 401, 'missing, invalid or forged admission headers must reject upgrade with HTTP 401');
    }
    console.log('PASS unauthenticated, invalid-cookie and forged-header upgrades rejected');
    const owner = await account(), outsider = await account(), member = await account();
    const createOrg = async cookie => {
      const id = ok(await call(base, '/api/orgs', { method: 'POST', cookie, json: { name: 'live fixture' } }), 'workspace creation').data.id;
      ensure(typeof id === 'string' && !!id, 'workspace must return id'); return id;
    };
    const org = await createOrg(owner.cookie), foreign = await createOrg(outsider.cookie);
    // Issuing an invite never adds membership; the member accepts explicitly.
    const invite = ok(await call(base, `/api/orgs/${org}/members`, { method: 'POST', cookie: owner.cookie, json: { email: member.email, role: 'developer' } }), 'member invitation');
    const inviteToken = invite.data.invite_token;
    ensure(typeof inviteToken === 'string' && !!inviteToken, 'member invitation must include a share token');
    ok(await call(base, '/api/auth/accept-invite', { method: 'POST', cookie: member.cookie, json: { token: inviteToken, password: member.password } }), 'member invitation acceptance');
    const control = await open(owner.cookie), memberSocket = await open(member.cookie), otherSocket = await open(outsider.cookie);
    const rename = async (cookie, id, marker) => ok(await call(base, `/api/orgs/${id}`, { method: 'PATCH', cookie, json: { name: marker } }), 'workspace rename');
    const marker = crypto.randomUUID();
    await rename(owner.cookie, org, marker);
    const first = await event(control, value => value.type === 'event' && value.detail === marker, 'owner event');
    await event(memberSocket, value => value.id === first.id, 'member event');
    ensure(first.org === org && first.action === 'org.rename' && Number.isSafeInteger(first.id) && first.id > 0, 'event must contain scoped audit metadata and replay cursor');
    const foreignMarker = crypto.randomUUID(); await rename(outsider.cookie, foreign, foreignMarker);
    await event(otherSocket, value => value.detail === foreignMarker, 'foreign positive control');
    await absent(otherSocket, value => value.detail === marker, 'another tenant must not receive workspace metadata');
    console.log('PASS hello, audit event and cross-tenant filtering with positive controls');
    control.close();
    const missedMarker = crypto.randomUUID(); await rename(owner.cookie, org, missedMarker);
    const reconnected = await open(owner.cookie, `/api/live?since=${first.id}`);
    const replay = await event(reconnected, value => value.detail === missedMarker, 'persisted reconnect replay');
    ensure(replay.id > first.id && replay.org === org, 'replay must advance the cursor in the authorized workspace');
    ensure(!reconnected.events.some(value => value.detail === foreignMarker), 'replay must exclude foreign tenant events');
    console.log('PASS reconnect since cursor returns persisted authorized events');
    const app = ok(await call(base, `/api/orgs/${org}/apps`, { method: 'POST', cookie: owner.cookie, json: { name: 'live app' } }), 'app creation').data.id;
    const envs = ok(await call(base, `/api/apps/${app}/envs`, { cookie: owner.cookie }), 'environment listing').data;
    ensure(Array.isArray(envs) && envs.length >= 2, 'fixture must have two default environments');
    const env = envs[0].id, allowed = envs[1].id;
    const renameEnv = async (id, marker) => ok(await call(base, `/api/envs/${id}`, { method: 'PATCH', cookie: owner.cookie, json: { name: marker } }), 'environment rename');
    const envBefore = crypto.randomUUID().replaceAll('-', ''); await renameEnv(env, envBefore);
    await event(memberSocket, value => value.detail === envBefore, 'member before restriction');
    ok(await call(base, `/api/envs/${env}/policy`, { method: 'PUT', cookie: owner.cookie, json: { restricted: true } }), 'environment restriction');
    const envAfter = crypto.randomUUID().replaceAll('-', ''); await renameEnv(env, envAfter);
    await event(reconnected, value => value.detail === envAfter, 'restricted owner positive control');
    const stillAllowed = crypto.randomUUID().replaceAll('-', ''); await renameEnv(allowed, stillAllowed);
    await event(memberSocket, value => value.detail === stillAllowed, 'unrestricted environment positive control');
    await absent(memberSocket, value => value.detail === envAfter, 'restriction applied after upgrade must suppress environment events');
    const scoped = ok(await call(base, `/api/apps/${app}/tokens`, { method: 'POST', cookie: owner.cookie,
      json: { name: 'live scoped', env_id: allowed, scopes: 'secrets:read' } }), 'scoped token creation').data.token;
    ensure(typeof scoped === 'string' && !!scoped, 'scoped token fixture must return token');
    const scopedSocket = await connect(base, '/api/live', undefined, { authorization: `Bearer ${scoped}` });
    if (scopedSocket.close) scopedSocket.close();
    ensure(scopedSocket.status === 403, 'environment-scoped token must be denied the workspace-wide live upgrade');
    ensure(!scopedSocket.events, 'denied environment-scoped upgrade must not create an event channel');
    console.log('PASS send-time environment restriction and environment-scoped upgrade denial');
    ok(await call(base, `/api/orgs/${org}/members/${member.id}`, { method: 'DELETE', cookie: owner.cookie }), 'membership removal');
    const removedMarker = crypto.randomUUID(); await rename(owner.cookie, org, removedMarker);
    await event(reconnected, value => value.detail === removedMarker, 'membership removal positive control');
    await absent(memberSocket, value => value.detail === removedMarker, 'removed membership must suppress org events on an existing socket');
    ok(await call(base, '/api/auth/logout', { method: 'POST', cookie: owner.cookie }), 'session logout');
    const login = ok(await call(base, '/api/auth/login', { method: 'POST', json: { email: owner.email, password: owner.password } }), 'independent writer login');
    const writerCookie = (login.headers.get('set-cookie') || '').split(';')[0];
    const writer = await open(writerCookie), logoutMarker = crypto.randomUUID();
    await rename(writerCookie, org, logoutMarker);
    await event(writer, value => value.detail === logoutMarker, 'post-logout writer positive control');
    await absent(reconnected, value => value.detail === logoutMarker, 'logout must stop future events on an already upgraded session');
    const stale = await connect(base, '/api/live', owner.cookie); if (stale.close) stale.close();
    ensure(stale.status === 401, 'logged-out cookie must not reconnect');
    console.log('PASS existing-socket membership revocation, logout and reconnect denial');
  } finally { for (const socket of sockets) socket.close(); }
}

async function main() {
  let temp, child;
  const messages = [], mailSockets = new Set();
  const mail = http.createServer(async (request, response) => {
    let raw = ''; for await (const chunk of request) raw += chunk;
    try { messages.push(JSON.parse(raw)); } catch { /* Signup below requires actual mail proof. */ }
    response.writeHead(200); response.end('{}');
  });
  mail.on('connection', socket => { mailSockets.add(socket); socket.once('close', () => mailSockets.delete(socket)); });
  try {
    await fs.access(path.join(root, 'crates/server/build/worker/shim.mjs'));
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-live-smoke-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir);
    const config = await writeWorkerConfig(configDir);
    const mailPort = await listen(mail), listener = net.createServer(), port = await listen(listener);
    await new Promise(resolve => listener.close(resolve));
    const base = `http://127.0.0.1:${port}`;
    const vars = { OPENWARP_ENV: 'development', OPENWARP_MASTER_KEY: crypto.randomBytes(32).toString('base64'),
      OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_PUBLIC_URL: base,
      OPENWARP_ALLOW_PRIVATE_EGRESS: '1', OPENWARP_EMAIL_WEBHOOK: `http://127.0.0.1:${mailPort}/mail` };
    const args = [...(process.env.WRANGLER ? [] : ['--no-install', 'wrangler']), 'dev', '--local', '--config', config,
      '--port', String(port), '--persist-to', path.join(temp, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(process.env.WRANGLER || 'npx', args, { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.resume(); child.stderr.resume();
    let spawnError; child.on('error', error => { spawnError = error; });
    let ready = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler exited before health succeeded');
      try { ready = (await call(base, '/health')).status === 200; } catch { /* Retry startup only. */ }
      if (ready) break; await sleep(100);
    }
    ensure(ready, 'prebuilt Worker bundle must become healthy');
    await exercise(base, async () => {
      const email = `live-${crypto.randomUUID()}@test.invalid`, password = crypto.randomUUID();
      const registered = ok(await call(base, '/api/auth/register', { method: 'POST', json: { email, password } }), 'verified fixture signup');
      ensure(registered.data.verification_required === true && !registered.data.token, 'disposable account must verify email before session issuance');
      let link;
      for (let i = 0; i < 100 && !link; i++) {
        link = String(messages.find(message => message.to === email)?.text || '').match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
        if (!link) await sleep(100);
      }
      ensure(!!link, 'verification mail must reach isolated sink');
      const url = new URL(link); ensure(url.origin === base, 'verification mail must use the local public URL');
      const verified = await call(base, url.pathname + url.search);
      ensure([200, 302, 303].includes(verified.status), 'mail verification must succeed');
      const login = ok(await call(base, '/api/auth/login', { method: 'POST', json: { email, password } }), 'verified fixture login');
      const cookie = (login.headers.get('set-cookie') || '').split(';')[0], id = login.data.user_id;
      ensure(/^ow_session=.+/.test(cookie) && typeof id === 'string' && !!id, 'verified login must return cookie and user id');
      ok(await call(base, '/api/me', { cookie }), 'cookie-only authentication');
      return { email, password, cookie, id };
    });
  } finally {
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
      await Promise.race([once(child, 'exit'), sleep(3000)]);
      if (child.exitCode === null && child.signalCode === null) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
        await once(child, 'exit');
      }
    }
    for (const socket of mailSockets) socket.destroy();
    if (mail.listening) await new Promise(resolve => mail.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    // Never print HTTP payloads, tokens, cookies, bindings or child-process logs.
    console.error(`FAIL live smoke: ${error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.message || error.name}`);
    process.exitCode = 1;
  });
}
