'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const app = fs.readFileSync(path.join(__dirname, '../src/app.rs'), 'utf8');
const ui = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');

function connectSources(policy) {
  return policy.match(/(?:^|;)\s*connect-src\s+([^;]+)/)[1].trim().split(/\s+/);
}

test('only the console CSP permits the exact Pwned Passwords origin', () => {
  const index = app.slice(app.indexOf('async fn index()'), app.indexOf('async fn security_headers'));
  assert.deepEqual(connectSources(index), ["'self'", 'https://api.pwnedpasswords.com']);
  for (const name of ['OAUTH_AUTH_CSP', 'LOCKBOX_CSP']) {
    const policy = app.match(new RegExp(`const ${name}: &str = "([^"]+)"`));
    assert.ok(policy, `${name} exists`);
    assert.deepEqual(connectSources(policy[1]), ["'self'"]);
  }
});

test('secret health is mounted for shared add/edit fields without save-triggered checks', () => {
  assert.match(ui, /function modal\(html,label\)\{[^\n]*mountSecretHealth\(\)/);
  assert.match(ui, /function mountSecretHealth\(\)\{let input=\$\('ns-val'\)\|\|\$\('ed-val'\)/);
  assert.match(ui, /data-health="local"/);
  assert.match(ui, /data-health="password"/);
  assert.match(ui, /data-health="email" hidden/);
  assert.match(ui, /checkPassword\(value,\{enabled:true,fetch:healthFetch\}\)/);
  assert.match(ui, /generation===HEALTH_GENERATION[^\n]*input.value===value/);
  assert.match(ui, /function closeModal\(\)\{HEALTH_GENERATION\+\+/);
  const stageFunctions = [...ui.matchAll(/(?:async )?function (?:stageNew|stageEdit|e2eStageNew|e2eStageEdit)\([^]*?(?=\n(?:async )?function )/g)];
  assert.equal(stageFunctions.length, 4);
  for (const match of stageFunctions) assert.doesNotMatch(match[0], /checkPassword|secret-health\/email|localStrength/);
});

test('button display declarations do not override the hidden email action', () => {
  const css = ui.match(/<style>([^]*?)<\/style>/)[1];
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)];
  for (const [, selector, declarations] of rules) {
    if (/display\s*:/.test(declarations) && /\bbutton\b/.test(selector)) {
      assert.match(selector, /:not\(\[hidden\]\)|\[hidden\]/,
        `button display rule must preserve hidden: ${selector}`);
    }
  }
});
