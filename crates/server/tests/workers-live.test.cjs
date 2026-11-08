'use strict';

// Source gates only. Execute scripts/worker-live-smoke.mjs for WebSocket proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const dir = path.join(__dirname, '../src');
const app = fs.readFileSync(path.join(dir, 'app.rs'), 'utf8');
const worker = fs.readFileSync(path.join(dir, 'worker.rs'), 'utf8');
const source = fs.readdirSync(dir).filter(f => f.endsWith('.rs')).map(f => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n');
const mask = s => s.replace(/r(#{0,16})"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, v => v.replace(/[^\n]/g, ' '));
function functions(s) {
  const code = mask(s), out = [];
  for (const match of code.matchAll(/\bfn\s+(\w+)\s*\(/g)) {
    const start = code.indexOf('{', match.index);
    if (start < 0) continue;
    let end = start + 1, depth = 1;
    while (end < code.length && depth) { if (code[end] === '{') depth++; if (code[end] === '}') depth--; end++; }
    out.push({ name: match[1], body: s.slice(start + 1, end - 1) });
  }
  return out;
}
const all = functions(source);
function reachable(roots) {
  const seen = new Set(), pending = [...roots], result = [];
  while (pending.length) {
    const fn = pending.pop();
    if (seen.has(fn)) continue;
    seen.add(fn); result.push(fn.body);
    const calls = new Set([...mask(fn.body).matchAll(/(?<![.\w])\b(\w+)\s*\(/g)].map(m => m[1]));
    const methods = new Set([...mask(fn.body).matchAll(/\.\s*((?:live|authorize|admit|validate|check|require|token)[A-Za-z0-9_]*)\s*\(/g)].map(m => m[1]));
    pending.push(...all.filter(f => calls.has(f.name) || methods.has(f.name)));
  }
  return result.join('\n');
}
const live = all.filter(f => /live|web_?socket/i.test(f.name));

test('Workers live route is implemented rather than an HTTP 501 capability stub', () => {
  assert.ok(!/route\("\/api\/live",\s*get\(live_unavailable\)\)/.test(app),
    'Workers /api/live still routes to the explicit HTTP 501 native-only stub');
  assert.match(worker, /WebSocketPair|web_socket|websocket/i, 'Workers must implement a WebSocket transport');
});

test('live event delivery rechecks credential validity and current org/environment authorization', () => {
  const delivery = reachable(live.filter(f => /send\s*\(|recv\s*\(|websocket/i.test(f.body + f.name)));
  for (const name of ['token_user', 'require_org', 'require_env', 'check_scope']) {
    assert.ok(new RegExp(`\\b${name}\\s*\\(`).test(delivery), `live delivery must recheck ${name}, including after admission`);
  }
});

test('Worker upgrade is admitted through shared authorization, not a path-only interception', () => {
  const upgrade = functions(worker).filter(f => /WebSocketPair|accept_web_socket|from_websocket/.test(f.body));
  for (const fn of upgrade) {
    const admission = reachable([fn]);
    assert.ok(/extensions\s*\(/.test(admission) || /token_user\s*\(/.test(admission),
      'Worker upgrade must consume a trusted shared response extension or execute shared authentication');
    assert.ok(/oneshot\s*\(/.test(admission) || /token_user\s*\(/.test(admission),
      'checking /api/live or client-supplied headers alone cannot admit a socket');
  }
});

test('live replay stays persisted, ordered, hour-bounded and capped at 500 rows', () => {
  const replay = reachable(live);
  assert.match(replay, /FROM live_events/);
  assert.match(replay, /id\s*>\s*\?/);
  assert.match(replay, /created_at\s*>=\s*\?/);
  assert.match(replay, /3600/);
  assert.match(replay, /ORDER BY id LIMIT 500/i);
});

test('Worker WebSocket callbacks cannot panic and attachments cannot serialize raw credentials', () => {
  for (const fn of functions(worker).filter(f => /web_?socket/i.test(f.name))) {
    assert.doesNotMatch(mask(fn.body), /\.(?:unwrap|expect)\s*\(|\bpanic!/, `${fn.name} must handle callback errors without panicking`);
  }
  for (const match of worker.matchAll(/serialize_attachment\s*\(([\s\S]*?)\)\s*[.;?]/g)) {
    assert.doesNotMatch(match[1], /bearer_token|authorization|cookie|raw_token|session_token/i,
      'Durable Object attachments must not persist raw session or bearer credentials');
  }
});
