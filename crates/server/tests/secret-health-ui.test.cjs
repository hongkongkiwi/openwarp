'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
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

function consoleFunction(name) {
  const start = ui.indexOf(`\nfunction ${name}(`);
  assert.ok(start >= 0, `${name} must exist`);
  const end = ui.slice(start + 1).search(/\n(?:async )?function /);
  assert.ok(end >= 0, `${name} must have a bounded source body`);
  return ui.slice(start + 1, start + 1 + end);
}

function modalHarness() {
  const mounts = [], cancellations = [], shown = new Set();
  const modal = { innerHTML: '', setAttribute() {}, removeAttribute() {}, querySelector() { return null; } };
  const wrapper = { classList: { add: value => shown.add(value), remove: value => shown.delete(value), contains: value => shown.has(value) } };
  const context = vm.createContext({
    $: id => ({ modal, modalwrap: wrapper }[id] || null),
    document: { activeElement: null }, requestAnimationFrame() {},
    owAttr() {}, owApply() {},
    mountSecretHealth() { mounts.push(modal.innerHTML); },
    rejectVerification: error => cancellations.push(error.message),
  });
  vm.runInContext('let STEP_UP=null,HEALTH_GENERATION=0,PRODUCT_SERIAL=0,PRODUCT_DIALOG=null,LASTFOCUS=null;'
    + ['modal', 'closeModal', 'settleStepUp'].map(consoleFunction).join('\n'), context, { timeout: 1000 });
  return { modal, mounts, cancellations, shown, run: code => vm.runInContext(code, context, { timeout: 1000 }) };
}

test('secret health is mounted for shared add/edit fields without save-triggered checks', () => {
  const h = modalHarness();
  for (const id of ['ns-val', 'ed-val']) {
    const html = `<input id="${id}">`;
    h.run(`modal(${JSON.stringify(html)},'Secret editor')`);
    assert.equal(h.mounts.at(-1), html, 'health must mount after replacing the modal content');
  }
  assert.equal(h.mounts.length, 2, 'each editor must mount health exactly once');
  assert.match(ui, /function mountSecretHealth\(\)\{let input=\$\('ns-val'\)\|\|\$\('ed-val'\)/);
  assert.match(ui, /data-health="local"/);
  assert.match(ui, /data-health="password"/);
  assert.match(ui, /data-health="email" hidden/);
  assert.match(ui, /checkPassword\(value,\{enabled:true,fetch:healthFetch\}\)/);
  assert.match(ui, /generation===HEALTH_GENERATION[^\n]*input.value===value/);
  for (const verification of [false, true]) {
    h.run("modal('<input id=\"ed-val\">','Secret editor')");
    const generation = h.run('HEALTH_GENERATION');
    if (verification) h.run('STEP_UP={saved:null,reject:rejectVerification};');
    h.run('closeModal()');
    assert.ok(h.run('HEALTH_GENERATION') > generation, 'normal close and verification cancellation must invalidate pending health results');
    assert.equal(h.shown.has('show'), false, 'the closed dialog must not remain actionable');
    assert.equal(h.run('STEP_UP'), null);
  }
  assert.deepEqual(h.cancellations, ['Verification cancelled']);
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
