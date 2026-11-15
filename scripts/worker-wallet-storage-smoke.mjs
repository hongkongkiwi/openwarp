#!/usr/bin/env node
// Requires a fresh core Worker and an absolute WRANGLER for exactly 4.158.0. Never builds or installs.
// Public dummy wallet material only. Never fund or use these keys.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { writeWorkerConfig } from './worker-config-smoke.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIVATE = '0x0000000000000000000000000000000000000000000000000000000000000001';
const PHRASE = '  abandon  abandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon about  ';
const PRIVATE_CURRENT = '  opaque ${NORMAL}\nprivate trailing  ';
const RECOVERY_CURRENT = '\t recovery ${NORMAL}\nphrase trailing  ';
const expectedChecks = 7;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ensure = (condition, message) => assert.ok(condition, message);
const pbkdf2 = promisify(crypto.pbkdf2);
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const server = net.createServer(), port = await listen(server); await new Promise(resolve => server.close(resolve)); return port; }
async function files(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return (await Promise.all(entries.map(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : [path.join(dir, entry.name)]))).flat();
}
function localEnvironment() {
  return { ...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(OPENWARP_|CLOUDFLARE_|CF_)/.test(key) && !/^(DATABASE_URL|REDIS_URL|ADDR|https?_proxy|all_proxy|no_proxy)$/i.test(key))),
    WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' };
}
async function requireFreshBundle(wrangler) {
  ensure(typeof wrangler === 'string' && path.isAbsolute(wrangler), 'WRANGLER must explicitly name an installed absolute executable path');
  const { stdout } = await promisify(execFile)(wrangler, ['--version'], { cwd: root, timeout: 15000, maxBuffer: 65536, env: localEnvironment() });
  ensure(stdout.trim() === '4.158.0', 'wallet smoke requires exactly Wrangler 4.158.0');
  const build = path.join(root, 'crates/server/build');
  await fs.access(path.join(build, 'worker/shim.mjs'));
  const artifacts = (await files(build)).filter(file => /\.(wasm|mjs|js)$/.test(file));
  ensure(artifacts.some(file => file.endsWith('.wasm')), 'prebuilt Worker must contain an actual wasm artifact');
  const inputs = ['Cargo.toml', 'Cargo.lock', 'crates/server/Cargo.toml', 'crates/crypto/Cargo.toml', 'wrangler.toml'].map(file => path.join(root, file));
  for (const dir of ['crates/server/src', 'crates/server/migrations', 'crates/crypto/src', 'vendor']) inputs.push(...await files(path.join(root, dir)));
  const newestInput = Math.max(...await Promise.all(inputs.map(async file => (await fs.stat(file)).mtimeMs)));
  const oldestArtifact = Math.min(...await Promise.all(artifacts.map(async file => (await fs.stat(file)).mtimeMs)));
  ensure(oldestArtifact >= newestInput, 'stale Worker bundle is unqualified; rebuild current wallet sources before running this smoke');
}
async function call(base, route, { method = 'GET', cookie, token, grant, json } = {}) {
  ensure(!(cookie && token), 'fixture requests must choose cookie or Bearer transport explicitly');
  const response = await fetch(base + route, { method, redirect: 'manual', signal: AbortSignal.timeout(30000),
    headers: { ...(cookie ? { cookie, origin: base } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(grant ? { 'x-openwarp-step-up': grant } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }) },
    body: json === undefined ? undefined : JSON.stringify(json) });
  let data; try { data = JSON.parse(await response.text()); } catch { data = null; }
  return { status: response.status, headers: response.headers, data };
}
function ok(response, label) {
  ensure(response.status === 200 && response.data !== null, `${label} must return HTTP 200 JSON (got ${response.status})`);
  return response.data;
}
function field(value, key) { ensure(typeof value?.[key] === 'string' && !!value[key], `fixture response requires ${key}`); return value[key]; }
function row(rows, key) {
  ensure(Array.isArray(rows), 'secret response must contain an array');
  const matches = rows.filter(item => item.key === key); ensure(matches.length === 1, 'expected exactly one named fixture secret'); return matches[0];
}
function noWallet(value) {
  const text = JSON.stringify(value);
  for (const marker of [PRIVATE, 'abandon', 'opaque', 'private trailing', 'recovery ${NORMAL}', 'phrase trailing']) {
    ensure(!text.includes(marker), 'wallet plaintext must not escape the explicit reveal response');
  }
}
function denied(response, status, label) {
  ensure(response.status === status && typeof response.data?.error === 'string', `${label} must return HTTP ${status} JSON (got ${response.status})`);
  noWallet(response.data);
}
function challenged(response) {
  denied(response, 428, 'wallet reveal without unused VeryRisky proof');
  ensure(response.data.step_up_required === true && response.data.risk === 'very_risky' && response.data.email_required === true && response.data.totp_required === false,
    'wallet challenge must require actual email proof for this non-TOTP account');
}
function wrappedPrivateKey(key, plain) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return `owv2:${Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('base64')}`;
}

async function main() {
  let temp, child, config, port, base, mailUrl, owner, member, app, env, otherEnv, service, privateId, recoveryId, spentGrant;
  let phase = 'fresh bundle and isolated workerd fixture', checks = 0, passed = 0, failures = 0, fixtureReady = false;
  const wrangler = process.env.WRANGLER, messages = [], sockets = new Set(), credentials = [], proofCodes = [], successfulReveals = [];
  let mailFaults = 0;
  const mail = http.createServer(async (request, response) => {
    try {
      ensure(request.method === 'POST' && request.url === '/mail', 'mail sink accepts only its local POST route');
      let raw = ''; for await (const chunk of request) { raw += chunk; ensure(raw.length <= 65536, 'mail request must stay bounded'); }
      messages.push(JSON.parse(raw)); response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}');
    } catch { mailFaults++; response.writeHead(400); response.end('{}'); }
  });
  mail.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const master = crypto.randomBytes(32).toString('base64'); credentials.push(master);
  const cookieAuth = account => ({ cookie: account.cookie });
  const bearerAuth = account => ({ token: account.token });
  const api = (route, options = {}) => call(base, route, { ...cookieAuth(owner), ...options });
  const revealPath = (eid, sid) => `/api/envs/${eid}/secrets/${sid}/reveal`;
  async function stop() {
    const previous = child; child = undefined;
    if (!previous?.pid || previous.exitCode !== null || previous.signalCode !== null) return;
    try { process.kill(-previous.pid, 'SIGTERM'); } catch { previous.kill('SIGTERM'); }
    await Promise.race([once(previous, 'exit'), sleep(3000)]);
    if (previous.exitCode === null && previous.signalCode === null) {
      try { process.kill(-previous.pid, 'SIGKILL'); } catch { previous.kill('SIGKILL'); }
      await once(previous, 'exit');
    }
  }
  async function start() {
    ensure(!child, 'previous Wrangler must stop before restart');
    const vars = { OPENWARP_ENV: 'development', OPENWARP_MASTER_KEY: master, OPENWARP_PUBLIC_URL: base,
      OPENWARP_AUTH_PROVIDERS: 'password', OPENWARP_ALLOW_PRIVATE_EGRESS: '1',
      OPENWARP_EMAIL_PROVIDER: 'webhook', OPENWARP_EMAIL_WEBHOOK: mailUrl };
    const args = ['dev', '--local', '--config', config, '--ip', '127.0.0.1', '--port', String(port), '--persist-to', path.join(temp, 'state')];
    for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
    child = spawn(wrangler, args, { cwd: temp, detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: localEnvironment() });
    // Wrangler logs can contain credentials. Discard them without retaining diagnostic artifacts.
    child.stdout.resume(); child.stderr.resume();
    let spawnError; child.on('error', error => { spawnError = error; });
    let listening = false;
    for (let i = 0; i < 600; i++) {
      if (spawnError) throw spawnError;
      ensure(child.exitCode === null && child.signalCode === null, 'Wrangler must remain alive until readiness');
      listening = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1'); socket.setTimeout(100);
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false)); socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (listening) break; await sleep(100);
    }
    ensure(listening, 'local workerd listener must become ready within 60 seconds');
    for (let i = 0; i < 40; i++) {
      const health = await call(base, '/health');
      if (health.status === 200) { ensure(health.data?.ok === true && health.data.service === 'openwarp', 'health must identify the actual Worker'); return; }
      ensure(health.status === 503, `Worker initialization may return only HTTP 503 before healthy (got ${health.status})`); await sleep(100);
    }
    assert.fail('Worker must initialize its isolated Durable Object storage');
  }
  async function freshMail(before, email, needle) {
    for (let i = 0; i < 100; i++) {
      const text = messages.slice(before).filter(message => message.to === email).map(message => String(message.text || '')).find(text => text.includes(needle));
      if (text) return text; await sleep(100);
    }
    assert.fail('fresh account email must reach the isolated local sink');
  }
  async function account(label) {
    const email = `wallet-${label}-${crypto.randomUUID()}@test.invalid`;
    const kdf = ok(await call(base, `/api/auth/kdf?email=${encodeURIComponent(email)}`), 'KDF discovery');
    ensure(kdf.version === 2 && kdf.algo === 'pbkdf2-sha256' && kdf.iterations === 600000, 'fixture must use public client-derived authentication');
    const password = crypto.randomUUID(), derived = await pbkdf2(password, Buffer.from(kdf.salt, 'base64'), kdf.iterations, 64, 'sha256'), authKey = derived.subarray(0, 32);
    const pair = crypto.generateKeyPairSync('x25519'), before = messages.length;
    const registeredResponse = await call(base, '/api/auth/register-v2', { method: 'POST', json: { email, salt: kdf.salt, iterations: kdf.iterations, algo: kdf.algo,
      auth_key: authKey.toString('base64'), public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
      wrapped_privkey: wrappedPrivateKey(derived.subarray(32), pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)) } });
    const registered = ok(registeredResponse, 'client-auth registration');
    ensure(registered.verification_required === true && !registered.token && !registeredResponse.headers.has('set-cookie'), 'registration must not bypass mailbox verification');
    const link = (await freshMail(before, email, '/api/auth/verify?token=')).match(/https?:\/\/[^\s"<>]+\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0];
    ensure(!!link, 'registration email must contain a verification link');
    const verification = new URL(link); ensure(verification.origin === base, 'verification mail must target this loopback Worker');
    ensure([200, 302, 303].includes((await call(base, verification.pathname + verification.search)).status), 'mailbox verification must succeed');
    const challenge = ok(await call(base, '/api/auth/challenge', { method: 'POST', json: { email } }), 'client-auth challenge');
    const proof = crypto.createHmac('sha256', authKey).update(`${field(challenge, 'challenge')}|${field(challenge, 'challenge_id')}`).digest('hex');
    const login = await call(base, '/api/auth/login-v2', { method: 'POST', json: { email, challenge_id: challenge.challenge_id, proof } });
    const session = ok(login, 'verified client-auth login'), cookie = (login.headers.get('set-cookie') || '').split(';')[0];
    ensure(!session.mfa_required && /^ow_session=.+/.test(cookie), 'verified account must receive an actual cookie session');
    const result = { email, token: field(session, 'token'), cookie, id: field(session, 'user_id'), org: field(registered, 'org_id') };
    credentials.push(password, authKey.toString('base64'), proof, result.token, cookie.slice('ow_session='.length));
    return result;
  }
  async function grant(account, auth) {
    const before = messages.length;
    const started = ok(await call(base, '/api/auth/step-up/start', { ...auth, method: 'POST', json: { risk: 'very_risky' } }), 'VeryRisky email proof start');
    ensure(started.email_sent === true && started.risk === 'very_risky', 'proof start must send an actual VeryRisky email');
    const code = (await freshMail(before, account.email, 'Your verification code is ')).match(/Your verification code is (\d{6})\b/)?.[1];
    ensure(!!code, 'step-up email must contain a six-digit code'); proofCodes.push(code);
    const proved = ok(await call(base, '/api/auth/step-up/verify', { ...auth, method: 'POST', json: { challenge: field(started, 'challenge'), email_code: code } }), 'delivered email proof verification');
    ensure(proved.risk === 'very_risky', 'grant must retain its VeryRisky tier');
    const token = field(proved, 'token'); credentials.push(token, started.challenge); return token;
  }
  async function reveal(account, auth, sid, value, proof) {
    const data = ok(await call(base, revealPath(env, sid), { ...auth, grant: proof }), 'explicit current wallet reveal');
    ensure(Object.keys(data).length === 1 && data.value === value, 'explicit reveal must preserve exact current UTF-8 bytes without normalization or interpolation');
    successfulReveals.push({ actor: account.id, sid });
  }
  async function deploy(secrets) {
    const data = ok(await api(`/api/envs/${env}/secrets`, { method: 'PUT', json: { secrets } }), 'ordinary SSE secret PUT');
    ensure(data.deployed === secrets.length, 'PUT must persist every fixture binding'); noWallet(data);
  }
  async function list(auth, suffix = '') {
    const data = ok(await call(base, `/api/envs/${env}/secrets${suffix}`, auth), 'ordinary secret listing');
    ensure(Array.isArray(data.secrets), 'list must include secret rows'); noWallet(data); return data.secrets;
  }
  async function masked(auth, version, suffix = '') {
    const rows = await list(auth, suffix);
    for (const [key, type, sid, storedPath] of [['PRIVATE', 'wallet_private_key', privateId, '/team/'], ['RECOVERY', 'wallet_recovery_phrase', recoveryId, '/other/']]) {
      const item = row(rows, key);
      ensure(item.type === type && item.value === null && item.version === version && item.path === storedPath, 'lists must preserve typed wallet metadata with null values');
      ensure(item.decrypt_error === false, 'masked wallet must not be reported as a failed decryption');
      if (sid) ensure(item.id === sid, 'editing or restart must preserve wallet record identity');
    }
    ensure(row(rows, 'NORMAL').value === 'ordinary' && row(rows, 'CONFIG').value === 'ordinary', 'ordinary secret and config reads must still work');
    ensure(row(rows, 'SEALED').value === null, 'sealed values must retain their existing list mask');
    return rows;
  }
  async function history(sid, count, wallet = true) {
    const data = ok(await api(`/api/secrets/${sid}/history`), 'secret history');
    ensure(Array.isArray(data) && data.length === count, 'history must retain each committed version');
    if (wallet) { ensure(data.every(item => item.value === '[WALLET]'), 'every wallet history version must be masked'); noWallet(data); }
    return data;
  }
  async function check(name, run) { phase = name; checks++; await run(); passed++; console.log(`PASS ${name}`); }
  try {
    await requireFreshBundle(wrangler);
    temp = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-worker-wallet-storage-'));
    const configDir = path.join(temp, 'config'); await fs.mkdir(configDir); config = await writeWorkerConfig(configDir);
    port = await freePort(); base = `http://127.0.0.1:${port}`; mailUrl = `http://127.0.0.1:${await listen(mail)}/mail`;
    await start(); owner = await account('owner'); member = await account('member');
    ensure(ok(await api('/api/instance'), 'isolated instance ownership').instance_owner === true, 'first verified account must own this isolated Worker');
    app = field(ok(await api(`/api/orgs/${owner.org}/apps`, { method: 'POST', json: { name: 'Worker wallet storage' } }), 'application creation'), 'id');
    const envs = ok(await api(`/api/apps/${app}/envs`), 'environment listing');
    ensure(Array.isArray(envs), 'application must list environments');
    env = envs.find(item => item.name === 'Development')?.id; otherEnv = envs.find(item => item.name === 'Staging')?.id;
    ensure(typeof env === 'string' && typeof otherEnv === 'string' && env !== otherEnv && [env, otherEnv].every(id => envs.find(item => item.id === id)?.mode === 'sse'), 'fixture needs distinct real SSE environments');
    const invited = ok(await api(`/api/orgs/${owner.org}/members`, { method: 'POST', json: { email: member.email, role: 'developer' } }), 'developer invitation');
    const accepted = ok(await call(base, '/api/auth/accept-invite-v2', { ...bearerAuth(member), method: 'POST', json: { token: field(invited, 'invite_token') } }), 'existing verified account invitation consent');
    ensure(accepted.org_id === owner.org && accepted.user_id === member.id && accepted.role === 'developer', 'path-control fixture must join by public invitation consent');
    const minted = ok(await api(`/api/apps/${app}/tokens`, { method: 'POST', json: { name: 'wallet-read-only', env_id: env, expires_in: 3600, scopes: 'secrets:read' } }), 'scoped automation read token mint');
    service = field(minted, 'token'); credentials.push(service);
    ensure(minted.scopes === 'secrets:read' && ok(await call(base, '/api/me', { token: service }), 'automation identity').env_scope === env, 'control credential must be actual environment-scoped automation');
    fixtureReady = true;
    await check('Worker SSE stores both wallet types while ordinary lists expose only typed null values', async () => {
      await deploy([{ key: 'PRIVATE', path: '/team/', type: 'wallet_private_key', value: PRIVATE },
        { key: 'RECOVERY', path: '/other/', type: 'wallet_recovery_phrase', value: PHRASE },
        { key: 'NORMAL', value: 'ordinary' }, { key: 'CONFIG', type: 'config', value: '${NORMAL}' }, { key: 'SEALED', type: 'sealed', value: 'dummy-sealed' }]);
      const rows = await masked(cookieAuth(owner), 1); ensure(rows.length === 5, 'initial PUT must create exactly the five fixture records');
      privateId = field(row(rows, 'PRIVATE'), 'id'); recoveryId = field(row(rows, 'RECOVERY'), 'id');
      await masked(bearerAuth(owner), 1); await masked({ token: service }, 1);
    });
    await check('Worker reveal requires real one-use email proof and refuses automation and wrong environment', async () => {
      const route = revealPath(env, privateId);
      denied(await call(base, route), 401, 'unauthenticated reveal'); challenged(await api(route));
      const proof = await grant(owner, cookieAuth(owner));
      denied(await call(base, route, { token: service, grant: proof }), 403, 'automation reveal with owner proof');
      denied(await call(base, route, { cookie: `ow_session=${service}`, grant: proof }), 401, 'automation credential in cookie');
      denied(await api(revealPath(otherEnv, privateId), { grant: proof }), 404, 'wallet id through wrong environment');
      await reveal(owner, cookieAuth(owner), privateId, PRIVATE, proof); challenged(await api(route, { grant: proof }));
      const bearerProof = await grant(owner, bearerAuth(owner));
      await reveal(owner, bearerAuth(owner), recoveryId, PHRASE, bearerProof);
      challenged(await call(base, revealPath(env, recoveryId), { ...bearerAuth(owner), grant: bearerProof }));
    });
    await check('Worker edits reveal only exact current wallet bytes and mask every historical version', async () => {
      await deploy([{ key: 'PRIVATE', path: '/team/', type: 'wallet_private_key', value: PRIVATE_CURRENT },
        { key: 'RECOVERY', path: '/other/', type: 'wallet_recovery_phrase', value: RECOVERY_CURRENT }]);
      const rows = await masked(cookieAuth(owner), 2);
      for (const [sid, value, auth] of [[privateId, PRIVATE_CURRENT, cookieAuth(owner)], [recoveryId, RECOVERY_CURRENT, bearerAuth(owner)]]) {
        const proof = await grant(owner, auth); await reveal(owner, auth, sid, value, proof);
        challenged(await call(base, revealPath(env, sid), { ...auth, grant: proof })); await history(sid, 2); spentGrant = proof;
      }
      const normal = await history(field(row(rows, 'NORMAL'), 'id'), 1, false);
      ensure(normal[0].value === 'ordinary', 'ordinary history must remain readable');
      const sealed = await history(field(row(rows, 'SEALED'), 'id'), 1, false);
      ensure(sealed[0].value === '[SEALED]', 'sealed history must retain its existing mask');
    });
    await check('Worker references never resolve wallets and both exports omit wallet bindings', async () => {
      await deploy([{ key: 'PRIVATE_ALIAS', value: '${PRIVATE}' }, { key: 'PHRASE_ALIAS', value: '${/other/RECOVERY}' },
        { key: 'CHAINED', value: 'prefix-${PRIVATE_ALIAS}' }, { key: 'NORMAL_ALIAS', value: 'prefix-${NORMAL}' }]);
      for (const auth of [cookieAuth(owner), { token: service }]) for (const query of ['', '?raw=1', '?base=1']) {
        const rows = await masked(auth, 2, query); ensure(rows.length === 9, 'aliases must not replace wallet bindings');
        ensure(row(rows, 'PRIVATE_ALIAS').value === '${PRIVATE}' && row(rows, 'PHRASE_ALIAS').value === '${/other/RECOVERY}' && row(rows, 'CHAINED').value === 'prefix-${PRIVATE}', 'direct, path-qualified and chained wallet references must remain unresolved');
        ensure(row(rows, 'NORMAL_ALIAS').value === 'prefix-ordinary', 'ordinary references must still resolve');
      }
      const ownerProof = await grant(owner, cookieAuth(owner));
      for (const [auth, suffix, proof] of [[cookieAuth(owner), '', ownerProof], [{ token: service }, '', undefined], [{ token: service }, '?base=1', undefined]]) {
        const exported = ok(await call(base, `/api/envs/${env}/export${suffix}`, { ...auth, grant: proof }), 'ordinary consumer export'); noWallet(exported);
        ensure(Array.isArray(exported.secrets) && exported.secrets.length === 6, 'exports must omit wallets and sealed records, not substitute empty values');
        ensure(!exported.secrets.some(item => ['PRIVATE', 'RECOVERY', 'SEALED'].includes(item.key)), 'exports must not include wallet bindings');
        ensure(row(exported.secrets, 'NORMAL').value === 'ordinary' && row(exported.secrets, 'NORMAL_ALIAS').value === 'prefix-ordinary', 'exported ordinary values must remain usable');
        ensure(typeof exported.text === 'string' && exported.text.split('\n').includes('NORMAL=ordinary') && !exported.text.split('\n').some(line => /^(PRIVATE|RECOVERY|SEALED)=/.test(line)), 'text export must omit wallet names and retain ordinary values');
      }
    });
    await check('Worker developer path denial preserves proof for one allowed wallet reveal', async () => {
      const policy = async (eid, prefix) => ok(await api(`/api/envs/${eid}/path-policy/developer`, { method: 'PUT', json: { rules: [{ prefix, capabilities: ['read'] }] } }), 'developer read path policy');
      await policy(otherEnv, '/unrelated/');
      challenged(await call(base, revealPath(env, privateId), bearerAuth(member)));
      await policy(env, '/team/');
      const rows = await list(bearerAuth(member));
      ensure(rows.length === 1 && row(rows, 'PRIVATE').value === null, 'developer list must include only the permitted masked wallet');
      challenged(await call(base, revealPath(env, privateId), bearerAuth(member)));
      const proof = await grant(member, bearerAuth(member));
      denied(await call(base, revealPath(env, recoveryId), { ...bearerAuth(member), grant: proof }), 403, 'wallet outside developer read path');
      await reveal(member, bearerAuth(member), privateId, PRIVATE_CURRENT, proof);
      challenged(await call(base, revealPath(env, privateId), { ...bearerAuth(member), grant: proof }));
    });
    await check('Worker rejects wallet type downgrades without changing stored versions', async () => {
      for (const [key, storedPath, otherType] of [['PRIVATE', '/team/', 'wallet_recovery_phrase'], ['RECOVERY', '/other/', 'wallet_private_key']]) {
        for (const type of [undefined, 'secret', otherType]) {
          const secret = { key, path: storedPath, value: 'replacement', ...(type ? { type } : {}) };
          denied(await api(`/api/envs/${env}/secrets`, { method: 'PUT', json: { secrets: [secret] } }), 400, 'wallet type change');
        }
      }
      denied(await api(`/api/envs/${env}/secrets`, { method: 'PUT', json: { secrets: [{ key: 'UNKNOWN', type: 'wallet_typo', value: 'dummy' }] } }), 400, 'unknown secret type');
      denied(await api(`/api/envs/${env}/secrets`, { method: 'PUT', json: { secrets: [{ key: 'SEALED', type: 'secret', value: 'replacement' }] } }), 400, 'existing sealed downgrade');
      const rows = await masked(cookieAuth(owner), 2); ensure(rows.length === 9, 'invalid writes must not add or remove records');
      await history(privateId, 2); await history(recoveryId, 2);
    });
    await check('Worker same-key cold restart retains masks, one-use state and plaintext-free reveal audits', async () => {
      await stop(); await start();
      ensure(ok(await api('/api/me'), 'persisted owner account session').id === owner.id, 'restart must recover the original verified session');
      await masked(cookieAuth(owner), 2); await masked({ token: service }, 2); await history(privateId, 2); await history(recoveryId, 2);
      challenged(await call(base, revealPath(env, recoveryId), { ...bearerAuth(owner), grant: spentGrant }));
      const audit = ok(await api(`/api/orgs/${owner.org}/audit?limit=1000`), 'persisted workspace audit');
      ensure(Array.isArray(audit), 'audit must contain persisted rows'); noWallet(audit);
      const reveals = audit.filter(item => item.action === 'wallet.reveal');
      ensure(reveals.length === successfulReveals.length && reveals.length === 5, 'only successful reveals must create exactly one wallet audit each');
      for (const expected of successfulReveals) {
        const count = successfulReveals.filter(item => item.actor === expected.actor && item.sid === expected.sid).length;
        ensure(reveals.filter(item => item.actor === expected.actor && item.detail === expected.sid && item.env_id === env && item.app_id === app).length === count, 'reveal audits must identify the correct actor, environment and wallet id');
      }
      const text = JSON.stringify(audit);
      for (const credential of credentials) ensure(!text.includes(credential), 'audit must not contain session, authentication or proof credentials');
      for (const entry of audit) for (const code of proofCodes) ensure(!String(entry.detail || '').split(/[^A-Za-z0-9]+/).includes(code), 'audit details must not contain emailed verification codes');
      ensure(mailFaults === 0, 'mail fixture must receive only valid bounded requests');
    });
  } catch (error) {
    failures++;
    const reason = error instanceof assert.AssertionError ? error.message.split('\n')[0] : error.code || error.name;
    console.error(`${fixtureReady ? 'FAIL' : 'UNQUALIFIED'} ${phase}: ${reason}`);
  } finally {
    await stop(); for (const socket of sockets) socket.destroy();
    if (mail.listening) await new Promise(resolve => mail.close(resolve));
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
  const qualified = fixtureReady && checks === expectedChecks && passed === expectedChecks && failures === 0;
  console.log(`${passed}/${expectedChecks} Worker wallet storage checks passed, ${checks} attempted, ${failures} failures, fixture ${qualified ? 'qualified' : 'unqualified'}`);
  process.exitCode = qualified ? 0 : 1;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
