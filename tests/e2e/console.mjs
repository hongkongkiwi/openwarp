#!/usr/bin/env node
// Real-browser authenticated console pass: boots a private server, registers a
// user, injects the session into a headless Chrome console, walks the pages,
// and checks theme and language persistence. Local only; not wired into CI.
// Run after `cargo build -p openwarp-server`: node tests/e2e/console.mjs
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import net from 'node:net';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHmac, randomUUID} from 'node:crypto';

const ROOT = new URL('../../', import.meta.url).pathname;
const BIN = join(ROOT, 'target/debug/openwarp-server');
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const AUTH_KEY = Buffer.alloc(32, 3);
const b64 = (b) => b.toString('base64');
const results = [];
const step = (name, ok, note = '') => { results.push({name, ok, note}); console.error(`${ok ? 'PASS' : 'FAIL'} ${name}${note ? ' — ' + note : ''}`); };
const phase = (name) => console.error(`.. ${name}`);
const bounded = (p, ms, what) => Promise.race([p, new Promise((_, j) => setTimeout(() => j(new Error(`timeout after ${ms}ms in ${what}`)), ms))]);

// --- mail sink ------------------------------------------------------------
const mails = [];
const sink = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => { try { mails.push(JSON.parse(body)); } catch {} res.writeHead(200, {'Content-Length': 2}).end('{}'); });
});
await new Promise((r) => sink.listen(0, '127.0.0.1', r));
const sinkPort = sink.address().port;

// --- server ---------------------------------------------------------------
const dir = mkdtempSync(join(tmpdir(), 'openwarp-e2e-'));
const port = await new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const base = `http://127.0.0.1:${port}`;
const child = spawn(BIN, [], {
  env: {PATH: process.env.PATH, DATABASE_URL: `sqlite://${dir}/test.db`, ADDR: `127.0.0.1:${port}`, OPENWARP_PUBLIC_URL: base, OPENWARP_EMAIL_WEBHOOK: `http://127.0.0.1:${sinkPort}/mail`, TOKIO_WORKER_THREADS: '2'},
  stdio: ['ignore', 'ignore', 'ignore'],
});
const http = async (method, path, token = '', body) => {
  const res = await fetch(base + path, {method, signal: AbortSignal.timeout(15000), headers: {...(token ? {authorization: `Bearer ${token}`} : {}), ...(body ? {'content-type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined, redirect: 'manual'});
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return {status: res.status, json, cookies: res.headers.getSetCookie ? res.headers.getSetCookie() : []};
};
const deadline = Date.now() + 20000;
phase('server boot');
while (true) { try { if ((await http('GET', '/health')).status < 300) break; } catch {} if (Date.now() > deadline) { console.error('server did not become healthy'); process.exit(1); } await new Promise((r) => setTimeout(r, 150)); }

// --- account over HTTP ----------------------------------------------------
phase('account over http');
const email = 'e2e@test.invalid';
const reg = await http('POST', '/api/auth/register-v2', '', {email, salt: b64(Buffer.alloc(16, 1)), iterations: 600000, algo: 'pbkdf2-sha256', auth_key: b64(AUTH_KEY), public_key: b64(Buffer.alloc(32, 5)), wrapped_privkey: 'owv2:' + b64(Buffer.alloc(40, 9))});
if (reg.status !== 200) { console.error('register failed', reg.status, reg.json); process.exit(1); }
const findLink = () => mails.map((m) => JSON.stringify(m)).reverse().map((s) => s.match(/\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0]).find(Boolean);
let link = findLink();
for (let i = 0; i < 100 && !link; i++) { await new Promise((r) => setTimeout(r, 100)); link = findLink(); }
if (!link || (await http('GET', link)).status !== 200) { console.error('verification link missing or verify failed'); process.exit(1); }
const ch = (await http('POST', '/api/auth/challenge', '', {email})).json;
const proof = createHmac('sha256', AUTH_KEY).update(`${ch.challenge}|${ch.challenge_id}`).digest('hex');
const login = await http('POST', '/api/auth/login-v2', '', {email, challenge_id: ch.challenge_id, proof});
if (login.status !== 200) { console.error('login failed', login.status, login.json); process.exit(1); }
const token = login.json.token;
// The console's emergency-status polls deliberately send no Authorization
// header and authenticate with the ow_session browser cookie instead, so the
// cookie must be installed in the browser or the shell bounces to the login
// screen seconds after enterApp().
const sess = (login.cookies.find((c) => c.startsWith('ow_session=')) || '').split(';')[0].slice('ow_session='.length);
if (!sess) { console.error('login set no ow_session cookie'); process.exit(1); }

// --- headless Chrome over CDP --------------------------------------------
const cdpDir = mkdtempSync(join(tmpdir(), 'ow-chrome-'));
rmSync(join(ROOT, '.agents/state/e2e-matrix/screens'), {recursive: true, force: true}); mkdirSync(join(ROOT, '.agents/state/e2e-matrix/screens'), {recursive: true});
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-proxy-server', '--remote-debugging-port=0', `--user-data-dir=${cdpDir}`, '--window-size=1440,900', 'about:blank'], {stdio: 'ignore'});
const cdpPort = await new Promise((r) => { const t0 = Date.now(); const t = setInterval(() => { try { const first = readFileSync(join(cdpDir, 'DevToolsActivePort'), 'utf8').split('\n')[0]; clearInterval(t); r(Number(first)); } catch {} if (Date.now() - t0 > 15000) { clearInterval(t); r(0); } }, 100); });
if (!cdpPort) { console.error('chrome devtools endpoint missing'); process.exit(1); }
let ws = null;
const target = await (await fetch(`http://127.0.0.1:${cdpPort}/json/new?${encodeURIComponent('about:blank')}`, {method: 'PUT', signal: AbortSignal.timeout(10000)})).json();
phase('cdp websocket');
ws = new WebSocket(target.webSocketDebuggerUrl);
await bounded(new Promise((r, j) => { ws.onopen = r; ws.onerror = () => j(new Error('ws error')); }), 15000, 'ws open');
let mid = 0; const pending = new Map(); const exceptions = [];
ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } else if (m.method === 'Runtime.exceptionThrown') { if (!String(m.params.exceptionDetails?.text || '').includes('401')) exceptions.push(m.params.exceptionDetails?.text); } };
const send = (method, params = {}) => new Promise((r, j) => { const id = ++mid; pending.set(id, (m) => m.error ? j(new Error(m.error.message)) : r(m.result)); ws.send(JSON.stringify({id, method, params})); });
const evaluate = async (expression, awaitPromise = true) => (await send('Runtime.evaluate', {expression, awaitPromise, returnByValue: true})).result.value;
const shot = async (name) => { const v = await send('Page.captureScreenshot', {format: 'png'}); writeFileSync(join(ROOT, `.agents/state/e2e-matrix/screens/${name}.png`), Buffer.from(v.data, 'base64')); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
await send('Page.enable'); await send('Runtime.enable');
const ck = await send('Network.setCookie', {name: 'ow_session', value: sess, url: base + '/', path: '/'});
if (!ck.success) { console.error('chrome rejected the session cookie'); process.exit(1); }
const load = async (url) => { await send('Page.navigate', {url}); for (let i = 0; i < 100; i++) { try { if (await evaluate(`document.readyState !== 'loading'`)) break; } catch {} await sleep(200); } await sleep(400); };
const enterApp = async () => { await evaluate(`T=${JSON.stringify(token)}; ME=null; enterApp()`); for (let i = 0; i < 50; i++) { if (await evaluate(`!!document.querySelector('.navbtn')`)) return true; await sleep(150); } return false; };

try {
  phase('browser pass');
  await load(base + '/');
  step('console renders', !!(await evaluate(`document.getElementById('email')`)));

  await enterApp();
  const me = await evaluate(`ME && ME.email`);
  // sessionEnded() hides the shell but keeps ME populated, so visibility is
  // the difference between a live session and one bounced to the login card.
  const visible = await evaluate(`document.getElementById('shell').style.display !== 'none'`);
  step('authenticated shell', me === email && visible, `ME.email=${me} shellVisible=${visible}`);
  step('no js exceptions after login', exceptions.length === 0, `${exceptions.length} exceptions${exceptions.length ? ': ' + exceptions[0] : ''}`);

  const pages = await evaluate(`[...document.querySelectorAll('.navbtn')].map(b=>b.dataset.nav)`);
  for (const [i, v] of (pages || []).slice(0, 4).entries()) { await evaluate(`nav(${JSON.stringify(v)})`); await sleep(350); await shot(`page-${i}-${v}`); }
  step('navigation walks pages', (pages || []).length >= 2, `pages=${(pages || []).join(',')}`);
  await shot('page-shell');

  // Theme: system -> light -> dark, persisted in localStorage under ow_theme.
  await evaluate(`cycleTheme()`); const p1 = await evaluate(`localStorage.getItem('ow_theme')`);
  await load(base + '/'); const persisted1 = await evaluate(`document.documentElement.dataset.themePref`);
  await enterApp(); await evaluate(`cycleTheme()`); const theme2 = await evaluate(`document.documentElement.dataset.theme`);
  await shot('theme-dark');
  step('theme persists across reload', p1 === 'light' && persisted1 === 'light', `stored=${p1} reloaded=${persisted1}`);
  step('theme cycle reaches dark', theme2 === 'dark', `data-theme=${theme2}`);

  // Language: switch to the first non-default option; assert a translated node and persistence.
  const langs = await evaluate(`[...document.querySelectorAll('.langsel option')].map(o=>o.value)`);
  const alt = (langs || []).find((v) => v && v !== 'en' && v !== 'system');
  if (!alt) { step('language switch', false, 'no alternative language in .langsel'); }
  else {
    const before = await evaluate(`document.getElementById('authtitle') ? document.getElementById('authtitle').textContent : document.querySelector('[data-i18n]')?.textContent`);
    await evaluate(`owSetLang(${JSON.stringify(alt)})`); await sleep(300);
    const after = await evaluate(`document.getElementById('authtitle') ? document.getElementById('authtitle').textContent : document.querySelector('[data-i18n]')?.textContent`);
    await load(base + '/'); await sleep(300);
    const afterReload = await evaluate(`document.getElementById('authtitle') ? document.getElementById('authtitle').textContent : document.querySelector('[data-i18n]')?.textContent`);
    await shot(`lang-${alt}`);
    step('language switch translates', before !== after, `"${before}" -> "${after}"`);
    step('language persists across reload', afterReload === after, `reloaded="${afterReload}"`);
  }
  step('no js exceptions at end', exceptions.length === 0, `${exceptions.length} exceptions`);
} catch (e) {
  step('harness completed without error', false, String(e));
} finally {
  const fails = results.filter((r) => !r.ok).length;
  console.error(`\n${results.length - fails}/${results.length} steps passed; screenshots in .agents/state/e2e-matrix/screens/`);
  try { if (ws) ws.close(); } catch {}
  try { chrome.kill(); } catch {}
  child.kill(); sink.close();
  try { rmSync(dir, {recursive: true, force: true}); rmSync(cdpDir, {recursive: true, force: true}); } catch {}
  process.exit(fails ? 1 : 0);
}
