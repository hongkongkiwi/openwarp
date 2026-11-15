import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import net from 'node:net';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import {test as baseTest, expect} from 'playwright/test';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export {expect};
export async function poll(read, description, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await read(); if (value) return value; await delay(50); }
  throw new Error(`Timed out waiting for ${description}`);
}
export function good(response, description) {
  assert.equal(response.status, 200, `${description}: HTTP ${response.status}`);
  return response.json;
}

export const test = baseTest.extend({
  anonymousBootstraps: [0, {option: true}],
  stack: async ({}, use) => {
    const dir = mkdtempSync(join(tmpdir(), 'openwarp-browser-'));
    const mails = [];
    const sink = createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => { try { mails.push(JSON.parse(body)); res.writeHead(200).end('{}'); } catch { res.writeHead(400).end('{}'); } });
    });
    let child;
    try {
      await new Promise((resolve, reject) => { sink.once('error', reject); sink.listen(0, '127.0.0.1', resolve); });
      const port = await new Promise((resolve, reject) => {
        const socket = net.createServer(); socket.once('error', reject);
        socket.listen(0, '127.0.0.1', () => { const port = socket.address().port; socket.close(() => resolve(port)); });
      });
      const base = `http://127.0.0.1:${port}`;
      let spawnError;
      child = spawn(join(ROOT, 'target/debug/openwarp-server'), [], {env: {
        PATH: process.env.PATH, DATABASE_URL: `sqlite://${dir}/test.db`, ADDR: `127.0.0.1:${port}`,
        OPENWARP_PUBLIC_URL: base, OPENWARP_EMAIL_WEBHOOK: `http://127.0.0.1:${sink.address().port}/mail`, TOKIO_WORKER_THREADS: '2',
      }, stdio: 'ignore'});
      child.once('error', error => { spawnError = error; });
      const call = async (method, path, token = '', body) => {
        const response = await fetch(base + path, {method, redirect: 'manual', signal: AbortSignal.timeout(15000),
          headers: {...(token ? {authorization: `Bearer ${token}`} : {}), ...(body !== undefined ? {'content-type': 'application/json'} : {})},
          body: body === undefined ? undefined : JSON.stringify(body)});
        const text = await response.text(); let json; try { json = JSON.parse(text); } catch {}
        return {status: response.status, json, text, cookies: response.headers.getSetCookie()};
      };
      await poll(async () => {
        if (spawnError) throw spawnError;
        assert.equal(child.exitCode, null, 'private server exited before health');
        try { return (await call('GET', '/health')).status === 200; } catch { return false; }
      }, 'private server health');
      const source = readFileSync(join(ROOT, 'crates/server/src/ui.rs'), 'utf8');
      const marker = 'pub const INDEX: &str = r##"';
      const start = source.indexOf(marker) + marker.length, end = source.indexOf('"##;', start);
      assert.ok(start >= marker.length && end > start, 'INDEX raw string exists');
      assert.equal((await call('GET', '/')).text, source.slice(start, end), 'rebuild server: served INDEX differs from current ui.rs');
      await use({base, call, mails, dir});
    } finally {
      if (child?.pid && child.exitCode === null && child.signalCode === null) {
        const exited = once(child, 'exit'); child.kill('SIGTERM');
        const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
        try { await exited; } finally { clearTimeout(timer); }
      }
      if (sink.listening) { sink.closeAllConnections(); await new Promise(resolve => sink.close(resolve)); }
      rmSync(dir, {recursive: true, force: true});
    }
  },
  safety: [async ({page, stack, anonymousBootstraps, browserName}, use, testInfo) => {
    let pageErrors = 0, consoleErrors = 0, externalRequests = 0, unauthorizedResources = 0, anonymousMeResponses = 0;
    const responses = [], headerChecks = [], unauthorizedRoutes = {};
    page.on('pageerror', () => { pageErrors++; });
    page.on('console', message => {
      if (message.type() === 'error' && !/^Failed to load resource: the server responded with a status of 428\b/.test(message.text())) {
        consoleErrors++;
        if (/^Failed to load resource: the server responded with a status of 401\b/.test(message.text())) unauthorizedResources++;
      }
    });
    page.on('request', request => { if (!request.url().startsWith(stack.base + '/')) externalRequests++; });
    page.on('response', response => {
      if (response.status() === 401) {
        const path = new URL(response.url()).pathname;
        const label = ['/api/me', '/api/instance/edition'].includes(path) ? path : 'other';
        unauthorizedRoutes[label] = (unauthorizedRoutes[label] || 0) + 1;
      }
      const path = new URL(response.url()).pathname;
      if (anonymousBootstraps && response.status() === 401 && ['/api/me', '/api/instance/edition'].includes(path) && response.request().method() === 'GET') {
        headerChecks.push(response.request().allHeaders().then(headers => {
          assert.ok(!headers.cookie && !headers.authorization, 'anonymous bootstrap must carry no credentials');
          if (path === '/api/me') anonymousMeResponses++;
        }));
      }
      if (response.status() >= 400 && response.status() !== 428) responses.push(response.status());
    });
    await use();
    await Promise.all(headerChecks);
    testInfo.annotations.push({type: 'safe-browser-counts', description: JSON.stringify({pageErrors, consoleErrors, unauthorizedResources, anonymousMeResponses, unauthorizedRoutes, externalRequests, failedStatuses: responses})});
    assert.equal(pageErrors, 0, 'uncaught browser error count');
    assert.equal(externalRequests, 0, 'external browser request count');
    if (anonymousBootstraps) {
      assert.equal(anonymousMeResponses, anonymousBootstraps, 'credential-free anonymous bootstrap count');
      assert.deepEqual(unauthorizedRoutes, {'/api/instance/edition': anonymousBootstraps, '/api/me': anonymousBootstraps}, 'only expected anonymous GET routes fail');
      assert.deepEqual(responses, Array(anonymousBootstraps * 2).fill(401), 'only anonymous bootstrap resources fail');
      assert.equal(consoleErrors, unauthorizedResources, 'no non-resource console errors');
      assert.equal(unauthorizedResources, browserName === 'firefox' ? 0 : anonymousBootstraps * 2, 'expected engine-native resource message count');
    } else {
      assert.equal(consoleErrors, 0, 'unexpected console error count');
      assert.deepEqual(responses, [], 'unexpected failed resource statuses');
    }
  }, {auto: true}],
});

export async function register(stack, email, password = 'browser-fixture-password') {
  const before = stack.mails.length;
  const registration = good(await stack.call('POST', '/api/auth/register', '', {email, password}), 'register fixture');
  const path = await poll(() => stack.mails.slice(before).map(mail => JSON.stringify(mail).match(/\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0]).find(Boolean), 'verification email');
  good(await stack.call('GET', path), 'verify fixture');
  const response = await stack.call('POST', '/api/auth/login', '', {email, password});
  const login = good(response, 'login fixture');
  const cookie = response.cookies.find(value => value.startsWith('ow_session='))?.split(';')[0].slice('ow_session='.length);
  assert.ok(cookie, 'session cookie exists');
  const orgs = good(await stack.call('GET', '/api/orgs', login.token), 'fixture workspaces');
  return {email, password, kit: registration.recovery_kit, token: login.token, cookie, org: orgs[0]?.id, id: good(await stack.call('GET', '/api/me', login.token), 'fixture identity').id};
}
export async function enter(page, stack, actor) {
  await page.context().addCookies([{name: 'ow_session', value: actor.cookie, url: stack.base, httpOnly: true, sameSite: 'Lax'}]);
  await page.goto(stack.base);
  await expect(page.locator('#shell')).toBeVisible();
}
export async function appFixture(stack, actor, name = 'browser-app') {
  const app = good(await stack.call('POST', `/api/orgs/${actor.org}/apps`, actor.token, {name}), 'fixture app');
  const envs = good(await stack.call('GET', `/api/apps/${app.id}/envs`, actor.token), 'fixture envs');
  return {...app, name, env: envs[0]};
}
