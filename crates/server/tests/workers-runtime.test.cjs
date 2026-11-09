'use strict';

// Source contracts only, not evidence of workerd execution or bounded memory use.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const read = file => fs.readFileSync(path.join(__dirname, '../src', file), 'utf8');
const worker = read('worker.rs');
const http = read('http.rs');
const app = read('app.rs');
const integrations = read('integrations.rs');

function mask(source) {
  return source.replace(/r(#{0,16})"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    value => value.replace(/[^\n]/g, ' '));
}
function body(source, name) {
  const code = mask(source);
  const match = new RegExp(`\\bfn\\s+${name}\\s*\\(`).exec(code);
  assert.ok(match, `source must provide ${name}`);
  const start = code.indexOf('{', match.index);
  let depth = 1, end = start;
  while (++end < code.length && depth) {
    if (code[end] === '{') depth++;
    if (code[end] === '}') depth--;
  }
  assert.equal(depth, 0, `${name} body must be balanced`);
  return source.slice(start + 1, end - 1);
}
function contains(source, pattern, message) { assert.ok(pattern.test(source), message); }
function availableOnWasm(source, name) {
  const declaration = new RegExp(`((?:#\\[[^\\n]+\\]\\s*)*)(?:pub\\s+)?(?:async\\s+)?fn\\s+${name}\\s*\\(`, 'g');
  return [...source.matchAll(declaration)].filter(match => !/cfg\(not\(target_arch\s*=\s*"wasm32"/.test(match[1]))
    .map(match => body(source.slice(match.index + match[1].length), name));
}

test('Workers initialization enforces the shared sign-in configuration validator', () => {
  contains(worker, /\bvalidate_auth_env\s*\(/, 'Workers must reject invalid OPENWARP_AUTH_PROVIDERS before serving the app');
  const init = body(worker, 'new');
  assert.ok(init.indexOf('envcfg::init') < init.indexOf('validate_auth_env') && init.indexOf('validate_auth_env') < init.indexOf('router('),
    'sign-in validation must run after bindings are installed and before router creation');
});

test('production Workers require a pinned HTTPS public URL', () => {
  contains(worker, /crate::production\s*\(\s*\)/, 'Workers startup must distinguish production configuration');
  contains(worker, /https:\/\//, 'Workers production public URL validation must require HTTPS');
  assert.ok(!/let\s+pub_url\s*=\s*envcfg::var\("OPENWARP_PUBLIC_URL"\)\.unwrap_or_default\(\)/.test(worker),
    'production Workers must not silently use an empty public URL');
});

test('Workers enforce the body budget while reading, not after an unbounded buffer', () => {
  assert.ok(!/\breq\s*\.\s*bytes\s*\(\s*\)\s*\.\s*await/.test(mask(worker)),
    'Workers must not fully buffer req.bytes() before enforcing the 8 MiB limit');
  contains(worker, /MAX_BODY/, 'the Workers request budget must remain explicit');
  contains(worker, /\b413\b/, 'oversized bodies must remain HTTP 413');
});

test('scheduled maintenance observes dispatch failures and non-success responses', () => {
  const scheduled = body(worker, 'scheduled');
  assert.ok(!/let\s+_\s*=/.test(mask(scheduled)) && !/if\s+let\s+Ok\s*\(/.test(mask(scheduled)),
    'cron dispatch must not silently discard binding, request, or fetch failures');
  contains(scheduled, /status_code\s*\(|\.status\s*\(/, 'cron dispatch must inspect the Durable Object response status');
});

test('Workers outbound HTTP does not silently drop requested deadlines', () => {
  const timeout = body(http, 'timeout');
  assert.ok(!/^\s*self\s*$/.test(mask(timeout)), 'Workers RequestBuilder.timeout must not be a no-op');
  contains(http, /AbortController|AbortSignal|Delay|Timeout|select\s*\(|race|timeout_at/, 'Workers outbound deadlines need an executable timer or abort mechanism');
});

test('public internal maintenance stays hidden before Durable Object forwarding', () => {
  const fetch = body(worker, 'fetch');
  contains(fetch, /starts_with\("\/__internal\/"\)/, 'all public internal paths must be rejected');
  contains(fetch, /Response::error\("not found",\s*404\)/, 'public internal endpoints must return 404');
  assert.ok(fetch.indexOf('/__internal/') < fetch.indexOf('durable_object('), 'internal requests must be blocked before forwarding');
  contains(fetch, /content-length/, 'declared oversized bodies must retain the early rejection path');
  contains(fetch, /\b413\b/, 'declared oversized bodies must return 413');
});

test('Workers retain master-key validation and lossless header forwarding', () => {
  const init = body(worker, 'new');
  contains(init, /\[u8;\s*32\]/, 'Workers master key must remain exactly 32 bytes');
  contains(init, /oc::unb64/, 'Workers master key must remain base64 decoded');
  contains(body(worker, 'to_axum'), /headers_mut\(\)\.append\(/, 'request headers, including Cookie and Origin, must survive conversion');
  contains(body(worker, 'to_worker'), /out\.headers\(\)\.set\(/, 'response headers, including Set-Cookie, must survive conversion');
});

test('shared browser cookies and MCP origin checks retain their security attributes', () => {
  const cookie = body(app, 'session_cookie');
  for (const attribute of ['HttpOnly', 'SameSite=Lax', 'Secure']) contains(cookie, new RegExp(attribute), `${attribute} cookie attribute must remain available`);
  contains(body(app, 'mcp_auth'), /origin_matches\s*\(/, 'MCP must validate browser Origin');
  contains(body(app, 'mcp_auth'), /FORBIDDEN/, 'MCP must reject a mismatched browser Origin');
});

test('Workers OCI Vault uses real RSA signing instead of a native-only stub', () => {
  for (const name of ['oci_sign', 'oci_request', 'oci_vault_sync', 'oci_vault_test']) {
    const selected = availableOnWasm(integrations, name);
    assert.equal(selected.length, 1, `${name} must have one Workers implementation`);
    assert.ok(!/requires the native server|needs RSA request signing|NOT_IMPLEMENTED|\b501\b/.test(selected[0]),
      `${name} must not be an unsupported Workers stub`);
  }
  contains(availableOnWasm(integrations, 'oci_sign')[0], /\.sign\s*\(/, 'OCI requests must have a real RSA signature');
});

test('integration timestamps use the shared Workers-compatible clock', () => {
  contains(body(integrations, 'unix_now'), /crate::clock::now\s*\(/, 'integration signatures must use the shared runtime clock, not SystemTime on wasm');
});
