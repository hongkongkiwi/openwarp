'use strict';

// Structural regressions only. These do not execute KMS, rotation, or protocols.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = path.join(__dirname, '../src');
const read = file => fs.readFileSync(path.join(src, file), 'utf8');
function mask(source) {
  return source.replace(/r(#{0,16})"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    value => value.replace(/[^\n]/g, ' '));
}
function itemEnd(code, start) {
  let at = start, parens = 0, brackets = 0;
  for (; at < code.length; at++) {
    if (code[at] === '(') parens++;
    if (code[at] === ')') parens--;
    if (code[at] === '[') brackets++;
    if (code[at] === ']') brackets--;
    if (!parens && !brackets && /[;{,]/.test(code[at])) break;
  }
  assert.ok(at < code.length, 'Rust item must have a body or terminator');
  if (code[at] !== '{') return at + 1;
  let depth = 1;
  while (++at < code.length) {
    if (code[at] === '{') depth++;
    if (code[at] === '}' && --depth === 0) return at + 1;
  }
  assert.fail('Rust item body must be balanced');
}
function forTarget(source, wasm) {
  const cfg = /#\[cfg\(\s*(not\(\s*)?target_arch\s*=\s*"wasm32"\s*\)?\s*\)\]|#\[cfg\(test\)\]/g;
  const code = mask(source), edits = [];
  for (const match of source.matchAll(cfg)) {
    const enabled = !match[0].includes('(test)') && (match[1] ? !wasm : wasm);
    edits.push([match.index, enabled ? match.index + match[0].length : itemEnd(code, match.index + match[0].length)]);
  }
  for (const [start, end] of edits.reverse()) source = source.slice(0, start) + ' '.repeat(end - start) + source.slice(end);
  return source;
}
function functions(source, wasm) {
  if (wasm !== undefined) source = forTarget(source, wasm);
  const code = mask(source), out = [];
  const declaration = /((?:#\[[^\n]+\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>{}]*>)?\s*\(/g;
  for (const match of source.matchAll(declaration)) {
    if (!/\bfn\b/.test(code.slice(match.index, match.index + match[0].length))) continue;
    const start = code.indexOf('{', match.index + match[0].length);
    let depth = 1, end = start;
    while (++end < code.length && depth) {
      if (code[end] === '{') depth++;
      if (code[end] === '}') depth--;
    }
    assert.equal(depth, 0, `${match[2]} body must be balanced`);
    out.push({ name: match[2], cfg: match[1], declaration: match[0], signature: source.slice(match.index, start), text: source.slice(start + 1, end - 1) });
  }
  return out;
}
const app = functions(read('app.rs'));
const native = name => selected(app, name, false);
const worker = name => selected(app, name, true);
function selected(items, name, wasm) {
  const matches = items.filter(fn => fn.name === name && !(wasm
    ? /cfg\(not\(target_arch\s*=\s*"wasm32"/.test(fn.cfg)
    : /cfg\(target_arch\s*=\s*"wasm32"/.test(fn.cfg)));
  assert.equal(matches.length, 1, `${name} must have one selected implementation`);
  return matches[0].text;
}
function targetFunctions(wasm) {
  const lib = forTarget(read('lib.rs'), wasm);
  return [...lib.matchAll(/(?:#\[path\s*=\s*"([^"]+)"\]\s*)?pub\s+mod\s+(\w+)\s*;/g)]
    .flatMap(match => functions(read(match[1] || `${match[2]}.rs`), wasm)
      .map(fn => ({ ...fn, module: match[2] })));
}
const all = targetFunctions(true), nativeAll = targetFunctions(false);
function reach(text, items = all) {
  const seen = new Set();
  function visit(current, module) {
    let result = current;
    for (const match of mask(current).matchAll(/\b((?:\w+::)*)(\w+)\s*\(/g)) {
      const qualifier = match[1].split('::').filter(Boolean).at(-1);
      let candidates = items.filter(fn => fn.name === match[2]);
      if (qualifier && items.some(fn => fn.module === qualifier)) candidates = candidates.filter(fn => fn.module === qualifier);
      else if (!qualifier && candidates.some(fn => fn.module === module)) candidates = candidates.filter(fn => fn.module === module);
      for (const fn of candidates) {
        if (seen.has(fn)) continue;
        seen.add(fn);
        result += '\n' + visit(fn.text, fn.module);
      }
    }
    return result;
  }
  return visit(text);
}
function contains(text, pattern, message) { assert.ok(pattern.test(text), message); }
function portable(name) {
  const text = worker(name);
  assert.ok(!/NOT_IMPLEMENTED|requires the native server|\b501\b/.test(text), `${name} must not be a Workers-only unsupported stub`);
  return reach(text);
}
function durableFetch(source = read('worker.rs')) {
  const matches = functions(source, true).filter(fn => fn.name === 'fetch' && /&self\b/.test(fn.signature));
  assert.equal(matches.length, 1, 'Workers must have one Durable Object fetch entry');
  return matches[0].text;
}
function initialization(source = read('worker.rs'), items = all) {
  const fetch = durableFetch(source), code = mask(fetch);
  const gate = /if\s+let\s+Err\(\w+\)\s*=\s*self\.initialized\.get_or_try_init\(\|\|\s*async\s*\{/.exec(code);
  assert.ok(gate, 'Workers initialization must be fallible and retryable on the fetch path');
  const start = gate.index + gate[0].lastIndexOf('{'), end = itemEnd(code, start);
  const tail = /^\s*\)\s*\.await\s*\{/.exec(code.slice(end));
  assert.ok(tail, 'Workers must await initialization and handle failure before dispatch');
  const failureStart = end + tail[0].lastIndexOf('{'), failureEnd = itemEnd(code, failureStart);
  contains(fetch.slice(failureStart, failureEnd), /return\s+Response::error\([^;]+,\s*503\s*\)/,
    'initialization failure must return an explicit retryable error, never serve with an unverified key');
  for (const [pattern, message] of [
    [/\.oneshot\s*\(/, 'HTTP dispatch'],
    [/\bprocess_maintenance\s*\(/, 'cron maintenance'],
  ]) {
    const dispatch = pattern.exec(code);
    assert.ok(dispatch && dispatch.index > failureEnd, `master initialization must finish before ${message}`);
  }
  const body = fetch.slice(start + 1, end - 1);
  contains(body, /Kms::from_env\s*\(\s*\)\s*\?/, 'Workers startup must validate the configured KMS bridge and propagate failure');
  contains(body, /load_master\s*\([^;]+\)\s*\.await\s*\?/, 'Workers startup must load and verify the master root and propagate failure');
  contains(body, /install_kms\s*\(/, 'Workers startup must install KMS before serving requests');
  assert.ok(body.indexOf('load_master') < body.indexOf('initialize_master') && body.indexOf('load_master') < body.indexOf('install_kms'),
    'verified master loading must precede publishing the key and KMS');
  const load = selected(items, 'load_master', true);
  contains(load, /verify_master(?:_full)?\s*\([^;]+\)\s*\.await\s*\?/, 'master loading must verify persisted identity and propagate validation failure');
  return reach(body, items);
}
function liveContract(appSource = read('app.rs'), workerSource = read('worker.rs')) {
  // The live route lives in api_router's merge block (router only adds MCP),
  // so the contract searches both wiring functions for the registration.
  // The live route is wired inside api_router's merge block; search the whole
  // wasm-targeted source for the registration, then inspect the handler.
  const route = forTarget(appSource, true).match(/route\("\/api\/live",\s*get\((\w+)\)\)/);
  assert.ok(route, 'Workers must expose a live route');
  const routeBody = selected(functions(appSource, true), route[1], true);
  assert.ok(!/NOT_IMPLEMENTED|requires the native server|\b501\b/.test(routeBody), 'available Workers WebSockets must use real transport, not a capability stub');
  const admission = reach(routeBody, functions(appSource, true));
  contains(admission, /token_user\s*\(/, 'Workers live admission must authenticate the caller');
  contains(admission, /check_scope\s*\(/, 'Workers live admission must check token scope');
  contains(routeBody, /extensions_mut\s*\(\s*\)\s*\.insert\s*\(admission\)/, 'Workers live route must publish trusted admission only after validation');
  const fetch = durableFetch(workerSource);
  contains(fetch, /extensions\s*\(\s*\)\s*\.get::<crate::app::LiveAdmission>/, 'Worker upgrade must consume trusted application admission');
  contains(fetch, /WebSocketPair::new\s*\(/, 'Workers live must allocate a real socket pair');
  contains(fetch, /accept_web_socket\s*\(/, 'Workers live must accept the server socket');
  contains(fetch, /Response::from_websocket\s*\(/, 'Workers live must return the client socket');
  const dispatch = fetch.indexOf('.oneshot('), upgrade = fetch.indexOf('WebSocketPair::new(');
  assert.ok(dispatch >= 0 && dispatch < upgrade, 'shared application admission must run before upgrading a socket');
}
function kmsSource() {
  const lib = forTarget(read('lib.rs'), true);
  const declaration = [...lib.matchAll(/((?:#\[[^\n]+\]\s*)*)pub\s+mod\s+kms\s*;/g)]
    .find(match => !/cfg\(not\(target_arch\s*=\s*"wasm32"/.test(match[1]));
  assert.ok(declaration, 'Workers must expose a KMS module');
  return read(declaration[1].match(/path\s*=\s*"([^"]+)"/)?.[1] || 'kms.rs');
}

test('target-aware reach excludes native clocks, including native-only impl blocks', () => {
  const source = `
    #[cfg(not(target_arch = "wasm32"))]
    impl Clock { fn now() -> i64 { SystemTime::now(); 0 } }
    #[cfg(target_arch = "wasm32")]
    impl Clock { fn now() -> i64 { js_sys::Date::now() as i64 } }
    fn protocol() { Clock::now(); }
  `;
  const wasm = functions(source, true), native = functions(source, false);
  const portable = reach(selected(wasm, 'protocol', true), wasm);
  contains(portable, /js_sys::Date::now/, 'Workers reach must include the portable clock');
  assert.ok(!/SystemTime::now/.test(portable), 'Workers reach must exclude native clocks');
  contains(reach(selected(native, 'protocol', false), native), /SystemTime::now/, 'native reach must retain its clock');
});

test('initialization gate rejects missing KMS validation and missing persisted-key verification', () => {
  const source = read('worker.rs');
  assert.throws(() => initialization(source.replace('crate::kms::Kms::from_env()?', 'Ok(None)?')),
    /validate the configured KMS bridge/);
  const withoutVerifier = all.map(fn => fn.name === 'load_master'
    ? { ...fn, text: fn.text.replace(/verify_master(?:_full)?\([^;]+\)\s*\.await\s*\?;/g, '') } : fn);
  assert.throws(() => initialization(source, withoutVerifier), /verify persisted identity/);
});

test('initialization gate rejects HTTP or cron dispatch before the awaited gate', () => {
  const source = read('worker.rs');
  for (const dispatch of ['self.app.clone().oneshot(request).await?;', 'process_maintenance(&self.store).await;']) {
    const afterDispatch = source.replace('async fn fetch(&self, req: Request) -> Result<Response> {',
      `async fn fetch(&self, req: Request) -> Result<Response> { ${dispatch}`);
    assert.throws(() => initialization(afterDispatch), /initialization must finish before/);
  }
  assert.throws(() => initialization(source.replace('get_or_try_init', 'get_or_init')), /fallible and retryable/);
  assert.throws(() => initialization(source.replace('return Response::error("master initialization failed", 503);', 'console_error!("ignored");')),
    /explicit retryable error/);
});

test('live gate cannot pass using a native-only implementation or an explicit Workers stub', () => {
  const route = 'fn router() { route("/api/live", get(live_ws)); }';
  const nativeOnly = `${route}
    #[cfg(not(target_arch = "wasm32"))]
    fn live_ws() { live_admission(); WebSocketPair::new(); }
  `;
  assert.throws(() => liveContract(nativeOnly), /live_ws must have one selected implementation/);
  assert.throws(() => liveContract(`${nativeOnly}
    #[cfg(target_arch = "wasm32")]
    fn live_ws() { StatusCode::NOT_IMPLEMENTED; }
  `), /real transport, not a capability stub/);
  assert.throws(() => liveContract(read('app.rs'), read('worker.rs').replace('WebSocketPair::new()', 'Unavailable::new()')),
    /allocate a real socket pair/);
});

test('Workers copies KMS bindings and installs configured KMS instead of silently ignoring it', () => {
  const config = read('envcfg.rs');
  for (const key of ['OPENWARP_KMS_URL', 'OPENWARP_KMS_TOKEN', 'OPENWARP_KMS_KEY_ID']) {
    contains(config, new RegExp(`"${key}"`), `Workers must copy ${key} from bindings`);
  }
  const init = initialization();
  contains(init, /Kms::from_env\s*\(/, 'Workers startup must validate the configured KMS bridge');
  contains(init, /install_kms\s*\(/, 'Workers startup must install KMS before serving requests');
  assert.ok(!/^\s*Ok\(None\)\s*$/.test(selected(functions(kmsSource()), 'from_env', true)), 'configured KMS must not silently become local-master mode');
});

test('Workers KMS bridge performs asynchronous wrapping and unwrapping with HTTP errors propagated', () => {
  const source = kmsSource(), fns = functions(source);
  for (const name of ['wrap', 'unwrap']) {
    const fn = fns.find(fn => fn.name === name);
    assert.ok(fn && /\basync\s+fn\b/.test(fn.declaration), `Workers KMS ${name} must be asynchronous, not a blocking or unsupported facade`);
    assert.ok(!/requires the native server/.test(fn.text), `Workers KMS ${name} must call the bridge`);
  }
  contains(source, /owkms:/, 'KMS ciphertext must retain its key-id-bearing envelope');
  const request = reach(source, fns);
  contains(request, /crate::http::provider_post_bounded\s*\([^)]*\)\s*\.await/,
    'Workers KMS must await a real HTTP request through the shared bounded provider');
  const provider = selected(functions(read('http.rs'), true), 'provider_post_bounded', true);
  contains(provider, /worker::Fetch::Request\s*\(|send_with_signal\s*\(/, 'the Workers KMS provider must issue a real awaited fetch');
  contains(provider, /status_code\s*\(\s*\)/, 'KMS HTTP failure must not be treated as usable key material');
  assert.ok(!/reqwest::blocking|std::thread::spawn/.test(mask(source)), 'Workers KMS cannot use native blocking threads');
});

function masterInventoryContract(source) {
  const inventory = source.match(/const MASTER_STORES:[^]*?\n\];/);
  assert.ok(inventory, 'master rotation must declare its encrypted-store inventory');
  const stores = [...inventory[0].matchAll(/MasterStore \{ table: "([^"]+)", ids: &\[([^\]]+)\], col: "([^"]+)", predicate: "([^"]+)" \}/g)];
  const store = (table, column) => {
    const matches = stores.filter(entry => entry[1] === table && entry[3] === column);
    assert.equal(matches.length, 1, `master rotation must reencrypt ${table}.${column}`);
    return matches[0];
  };
  assert.equal(store('users', 'auth_key_enc')[2], '"id"', 'auth keys must be bound to their user identity');
  contains(store('meta', 'v')[4], /totp_pending:/, 'master rotation must preserve pending TOTP enrollment');
  store('ldap_configs', 'bind_password_enc');
  const implementation = source.match(/impl MasterStore \{([^]*?)\n\}/);
  assert.ok(implementation, 'inventory entries must have a real selection and update implementation');
  const methods = functions(implementation[0]);
  contains(selected(methods, 'select', false), /format!\("SELECT \* FROM \{\} WHERE \{\}",\s*self\.table,\s*self\.predicate\)/,
    'inventory selection must use the descriptor table and predicate');
  const updates = selected(methods, 'updates', false);
  contains(updates, /let value=db::s\(row,self\.col\); let id=db::s\(row,self\.ids\[0\]\)/,
    'rewrapping must read the descriptor ciphertext and record identity');
  contains(updates, /\("users",_\)\s*=>\s*Some\(auth_key_aad\(&id\)\)/,
    'rotated client-auth keys must retain their user-bound AAD');
  contains(updates, /Some\(aad\)=>oc::decrypt_symmetric_aad\(old,aad,&value\)/,
    'client-auth ciphertext must decrypt with the old master and user AAD');
  contains(updates, /Some\(aad\)=>oc::encrypt_symmetric_aad\(new,aad,&plain\)/,
    'client-auth plaintext must reencrypt with the new master and the same AAD');
  contains(updates, /None=>oc::decrypt_symmetric\(old,&value\)/,
    'pending TOTP and LDAP ciphertext must decrypt with the old master');
  contains(updates, /None=>oc::encrypt_symmetric\(new,&plain\)/,
    'pending TOTP and LDAP plaintext must reencrypt with the new master');
  contains(updates, /format!\("UPDATE \{\} SET \{\}=\? WHERE \{\}",self\.table,self\.col,self\.ids/,
    'rotation updates must write the descriptor column using its record identity');
  contains(updates, /let mut params=vec!\[json!\(encrypted\)\]/, 'the update must persist the replacement ciphertext');
  for (const wasm of [false, true]) {
    const rotation = selected(functions(source, wasm), 'rotate_master', wasm);
    contains(rotation, /for store in MASTER_STORES\s*\{/, 'both rotation targets must traverse the encrypted-store inventory');
    contains(rotation, /let rows=(?:tx|st\.db)\.query\(&store\.select\(\),&\[\]\)/,
      'rotation must snapshot each selected inventory store');
    contains(rotation, /for \(sql,params\) in store\.updates\(&rows,&old,&new\)/,
      'rotation must rewrap the snapshotted rows from the old to the new master');
    contains(rotation, wasm ? /statements\.push\(\(sql,params,Some\(1\)\)\)/ : /tx\.exec\(&sql,&params\)\?!=1/,
      'rotation must apply the generated updates with affected-row checks');
  }
}

test('master rotation preserves client-auth keys, pending TOTP, and LDAP credentials', () => {
  masterInventoryContract(read('app.rs'));
});

test('master rotation commits encrypted records atomically before publishing the new key', () => {
  const rotation = reach(native('rotate_master'), nativeAll);
  contains(rotation, /(\.checked_batch\s*\(\s*&statements|webhook_atomic\s*\(\s*move\s*\|tx\|)/, 'master rotation must use a shared atomic database batch, not individually committed ciphertext updates');
  contains(rotation, /decrypt_symmetric/, 'master rotation must preflight existing encrypted values');
  contains(rotation, /only the instance owner/, 'master rotation must retain instance-owner authorization');
  contains(rotation, /owkms:/, 'master rotation must recognize externally wrapped environment keys');
});

test('Workers master rotation uses the real rotation path', () => { portable('rotate_master'); });

test('Workers cold start validates persisted master-key identity before serving encrypted data', () => {
  const init = initialization();
  contains(init, /master.*(?:check|fingerprint|verifier)|(?:check|fingerprint|verifier).*master|master_key_check|key_check/i,
    'Workers startup must verify a persisted master-key identity so a stale binding after rotation fails closed');
  contains(init, /decrypt_symmetric|verify.*master|master.*verify|hash_token|Sha256|Hmac/i,
    'cold-start key identity must be checked cryptographically, not only decoded as 32 bytes');
});

test('Workers SAML reuses validation and replay boundaries with a portable clock', () => {
  const acs = portable('saml_acs');
  contains(acs, /SamlValidationContext|validate_response|validate_assertion/, 'SAML ACS must use protocol validation');
  contains(acs, /RequireCache|ReplayDetected|saml_replay/, 'SAML ACS must retain replay protection');
  assert.ok(!/SystemTime::now\s*\(/.test(mask(acs)), 'SAML validation must not call unsupported SystemTime::now on Workers');
  for (const name of ['saml_metadata', 'saml_start', 'get_saml_config', 'put_saml_config']) portable(name);
});

test('Workers OCSP and CRL fail closed while native paths stay real and clock-portable', () => {
  for (const name of ['ocsp_respond', 'ca_crl']) {
    const stub = worker(name);
    assert.ok(/NOT_IMPLEMENTED|requires the native server/.test(stub), `${name} must fail closed with an explicit unsupported error on Workers`);
    assert.ok(!/ocsp-response|pkix-crl|sign\s*\(/i.test(mask(stub)), `the ${name} stub must never synthesize protocol output`);
  }
  const ocsp = native('ocsp_respond'), crl = native('ca_crl');
  contains(ocsp, /application\/ocsp-response/, 'OCSP must emit a real protocol response');
  contains(crl, /application\/pkix-crl/, 'CRL must emit a real revocation list');
  // Wall-clock calls are native-only by design (certificate validity windows);
  // the Workers stubs must never touch a clock that panics on wasm, and the
  // native OCSP response must be built through the shared runtime clock.
  for (const name of ['ocsp_respond', 'ca_crl']) {
    assert.ok(!/OffsetDateTime::now_utc\s*\(|SystemTime::now\s*\(/.test(mask(worker(name))), `${name} Workers stub must not call unsupported wall-clock functions`);
  }
  contains(ocsp, /clock::system_time\s*\(/, 'native OCSP must sign through the shared runtime clock');
});

test('Workers live and passkey gaps remain explicit and never issue an unverified session', () => {
  liveContract();
  const mfa = functions(read('mfa.rs'), true);
  for (const name of ['passkey_register_start', 'passkey_register_finish', 'passkey_login_start', 'passkey_login_finish']) {
    const text = selected(mfa, name, true);
    if (/NOT_IMPLEMENTED/.test(text)) {
      contains(text, /Err\s*\(/, 'unsupported passkeys must fail closed');
      assert.ok(!/make_session\s*\(/.test(mask(text)), 'unsupported passkeys must never issue a session');
    } else {
      contains(reach(text), /finish_passkey_authentication|finish_passkey_registration|start_passkey_authentication|start_passkey_registration/,
        'implemented passkeys must use real WebAuthn verification, not a placeholder');
      const operation = name.includes('login') ? 'authentication' : 'registration';
      const phase = name.endsWith('finish') ? 'finish' : 'start';
      contains(reach(text), new RegExp(`\\b${phase}_passkey_${operation}\\s*\\(`),
        `${name} must execute its own WebAuthn ${phase} ${operation} operation`);
    }
  }
});
