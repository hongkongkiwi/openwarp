'use strict';

// Source contracts only. These do not execute Rust, cryptography, or workerd.
// Run with node --test crates/server/tests/workers-mfa.test.cjs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = path.join(__dirname, '../src');
const read = file => fs.readFileSync(path.join(src, file), 'utf8');

// Mask literals and comments when finding Rust item boundaries, not when checking SQL.
function mask(source) {
  return source.replace(/r(#{0,16})"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    value => value.replace(/[^\n]/g, ' '));
}
function itemEnd(source, start) {
  const code = mask(source);
  const first = code.slice(start).search(/[;{]/);
  assert.ok(first >= 0, 'Rust item must have a body or semicolon');
  let at = start + first;
  if (code[at] === ';') return at + 1;
  let depth = 1;
  while (++at < code.length) {
    if (code[at] === '{') depth++;
    if (code[at] === '}' && --depth === 0) return at + 1;
  }
  assert.fail('Rust item body must be balanced');
}
function forTarget(source, wasm) {
  // Both the old shim selection and a shared module with native-only WebAuthn work.
  const cfg = /#\[cfg\(\s*(not\(\s*)?target_arch\s*=\s*"wasm32"\s*\)?\s*\)\]/g;
  const edits = [];
  for (const match of source.matchAll(cfg)) {
    const enabled = match[1] ? !wasm : wasm;
    edits.push([match.index, enabled ? match.index + match[0].length : itemEnd(source, match.index + match[0].length)]);
  }
  for (const [start, end] of edits.reverse()) source = source.slice(0, start) + ' '.repeat(end - start) + source.slice(end);
  return source;
}
function functions(source) {
  const code = mask(source);
  const out = new Map();
  for (const match of code.matchAll(/\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>{}]*>)?\s*\(/g)) {
    const start = code.indexOf('{', match.index);
    assert.ok(start >= 0, `function ${match[1]} must have a body`);
    const end = itemEnd(source, start);
    out.set(match[1], source.slice(start + 1, end - 1));
  }
  return out;
}
function moduleFor(wasm) {
  const lib = forTarget(read('lib.rs'), wasm);
  const declaration = lib.match(/(?:#\[path\s*=\s*"([^"]+)"\]\s*)?pub\s+mod\s+mfa\s*;/);
  assert.ok(declaration, 'the selected target must expose the MFA module');
  const file = declaration[1] || 'mfa.rs';
  const source = forTarget(read(file), wasm);
  const fns = functions(source);
  const body = name => {
    assert.ok(fns.has(name), `${file} must provide ${name} on ${wasm ? 'Workers' : 'native'}`);
    return fns.get(name);
  };
  const reach = name => {
    const seen = new Set();
    function visit(current) {
      if (seen.has(current)) return '';
      seen.add(current);
      const text = body(current);
      const calls = mask(text);
      let result = text;
      for (const candidate of fns.keys()) {
        if (new RegExp(`\\b${candidate}\\s*\\(`).test(calls)) result += '\n' + visit(candidate);
      }
      return result;
    }
    return visit(name);
  };
  return { file, body, reach };
}
function contains(source, pattern, message) {
  // Keep failure output focused rather than printing account/security source.
  assert.ok(pattern.test(source), message);
}
function portable(module, name) {
  const source = module.reach(name);
  assert.ok(!/NOT_IMPLEMENTED|\b501\b/.test(source), `${name} must not be a native-only 501 on Workers`);
  return source;
}
function enrollment(module) {
  const required = module.reach('required');
  contains(required, /totp_enabled:/, 'MFA required must consult persisted TOTP enrollment, not constant false');
  contains(required, /email_mfa_enabled:/, 'MFA required must consult persisted email enrollment even when delivery is unavailable');
  contains(required, /FROM\s+passkeys\s+WHERE\s+user_id\s*=/i,
    'existing passkey-only accounts must still require MFA on Workers');
  const methods = module.reach('methods');
  for (const factor of ['totp', 'email', 'passkey']) {
    contains(methods, new RegExp(`"${factor}"`), `enrolled ${factor} must not disappear from MFA method discovery`);
  }
  assert.ok(!/^\s*(?:return\s+)?false\s*;?\s*$/.test(module.body('required')), 'required cannot unconditionally disable MFA');
}
function reauthentication(module) {
  const add = module.reach('reauth_add');
  contains(add, /password_known:/, 'adding another factor must retain the password-account reauthentication policy');
  contains(add, /pass_hash/, 'factor changes must load the current account password hash');
  contains(add, /verify_password\s*\(/, 'factor changes must verify the supplied password');
  contains(add, /UNAUTHORIZED/, 'missing or wrong reauthentication must be rejected');
  contains(module.reach('note_password_login'), /password_known:/, 'password sign-in must record that the account knows its password');
}
function totpAndRecovery(module) {
  const confirm = portable(module, 'confirm_totp');
  contains(confirm, /totp_pending:/, 'TOTP confirmation must inspect pending enrollment');
  contains(confirm, /decrypt_symmetric\s*\(/, 'TOTP confirmation must use the encrypted account secret');
  contains(confirm, /totp_code\s*\(/, 'TOTP confirmation must validate an authenticator code');
  const verify = portable(module, 'second_factor_ok');
  contains(verify, /totp_last:/, 'TOTP verification must retain durable replay protection');
  contains(verify, /totp_recovery:/, 'MFA verification must accept stored recovery codes');
  contains(verify, /hash_token\s*\(/, 'recovery code verification must compare hashed codes');
  contains(verify, /\.remove\s*\(/, 'an accepted recovery code must be consumed');
  contains(verify, /code\.is_empty\s*\(\)/, 'empty factor codes must be rejected for enrolled accounts');
  const issue = portable(module, 'issue_recovery_codes');
  contains(issue, /random_token\s*\(/, 'recovery code issuance must generate random codes, not an empty list');
  contains(issue, /hash_token\s*\(/, 'recovery codes must be hashed before storage');
}
function emailCodes(module) {
  const available = module.reach('email_available');
  contains(available, /MailConfig|mailer::/, 'email MFA availability must reflect configured delivery rather than constant false');
  const enroll = portable(module, 'email_enroll_start');
  contains(enroll, /token_user\s*\(/, 'email enrollment must authenticate the session');
  contains(enroll, /verify_password\s*\(/, 'email enrollment must retain reauthentication');
  contains(enroll, /send_email_result\s*\(/, 'email enrollment must deliver a real code using the portable mail path');
  const verify = portable(module, 'email_enroll_verify');
  contains(verify, /email_mfa_enabled:/, 'successful proof must persist email enrollment');
  contains(verify, /expires_at/, 'email codes must expire');
  contains(verify, /attempts/, 'email code guessing must remain bounded');
  contains(verify, /DELETE FROM email_codes/i, 'email proof must consume a stored code');
  const login = portable(module, 'email_login_send');
  contains(login, /mfa_challenges/, 'sending a login email must validate the password-stage challenge');
  contains(login, /rate_ok\s*\(/, 'email login delivery must remain rate limited');
}
function challenges(module) {
  const create = portable(module, 'new_challenge');
  contains(create, /INSERT INTO mfa_challenges/i, 'password-stage MFA must create a durable challenge');
  contains(create, /hash_token\s*\(/, 'MFA challenge tokens must be stored hashed');
  const lookup = module.reach('challenge_user');
  contains(lookup, /created_at|expires_at/, 'MFA challenge lookup must enforce expiration');
  contains(lookup, /return None|ok_or|filter\s*\(/, 'invalid or expired MFA challenges must not identify a user');
  contains(module.reach('consume_challenge'), /DELETE FROM mfa_challenges/i, 'completed MFA must consume the login challenge');
}

test('Workers enrollment cannot erase TOTP, email, or passkey-only MFA requirements', () => {
  enrollment(moduleFor(true));
});
test('Workers factor enrollment retains current-password reauthentication', () => {
  reauthentication(moduleFor(true));
});
test('Workers TOTP and recovery codes use real verification and replay state', () => {
  totpAndRecovery(moduleFor(true));
});
test('Workers email MFA retains delivery, proof, challenge, and attempt boundaries', () => {
  emailCodes(moduleFor(true));
});
test('Workers MFA login challenges remain durable, hashed, expiring, and consumable', () => {
  challenges(moduleFor(true));
});
test('shared login issues sessions only after the enrolled-factor gate', () => {
  const app = functions(read('app.rs'));
  const login = app.get('login');
  assert.ok(login, 'shared password login must exist');
  contains(login, /mfa::required\s*\(/, 'password login must consult MFA enrollment');
  assert.ok(login.indexOf('mfa::required') < login.indexOf('make_session('), 'password login must gate session issuance on MFA');
  contains(login, /return Ok\([\s\S]*mfa_required/, 'an enrolled account must return a challenge rather than fall through to a session');
  const complete = app.get('mfa_login');
  assert.ok(complete, 'shared MFA completion must exist');
  for (const call of ['challenge_user', 'second_factor_ok', 'consume_challenge']) {
    contains(complete, new RegExp(`mfa::${call}\\s*\\(`), `MFA completion must use ${call}`);
    assert.ok(complete.indexOf(`mfa::${call}`) < complete.indexOf('make_session('), `${call} must precede session issuance`);
  }
});
test('native MFA contracts remain intact and Workers passkeys may only fail explicitly', () => {
  const native = moduleFor(false);
  enrollment(native);
  reauthentication(native);
  totpAndRecovery(native);
  emailCodes(native);
  challenges(native);
  contains(native.reach('passkey_login_finish'), /finish_passkey_authentication\s*\(/, 'native WebAuthn must continue verifying assertions');
  const worker = moduleFor(true).reach('passkey_login_finish');
  if (/NOT_IMPLEMENTED|\b501\b/.test(worker)) {
    contains(worker, /Err\s*\(/, 'unsupported Workers passkeys must return an explicit error');
    assert.ok(!/make_session\s*\(/.test(worker), 'unsupported Workers passkeys must never issue a session');
  } else {
    contains(worker, /finish_passkey_authentication\s*\(/, 'supported Workers passkeys must verify an assertion');
  }
});
