'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
const mount = source.slice(source.indexOf('function mountSecretHealth()'), source.indexOf('async function loadHealthKeyStatus()'));

function harness(waitForResponse = false) {
  const buttons = Object.fromEntries(['local', 'password', 'email', 'enzoic', 'leakcheck', 'pair'].map(kind => [kind, { dataset: { health: kind } }]));
  const output = { textContent: '', appendChild() {} };
  const details = { open: true, addEventListener(_, fn) { this.toggle = fn; } };
  const box = { isConnected: true, querySelector(selector) {
    if (selector === 'details') return details;
    if (selector === '[data-health-pair-email]') return pairEmail;
    if (selector === '[data-health-pair-label]') return pairLabel;
    if (selector === '[data-health-result]') return output;
    return buttons[selector.match(/"([^"]+)"/)[1]];
  }, querySelectorAll() { return Object.values(buttons); } };
  const input = { value: 'person@example.com', parentElement: { appendChild() {} }, addEventListener() {} };
  const pairEmail = { value: 'pair@example.invalid', addEventListener() {} }, pairLabel = { hidden: true };
  const requests = [];
  let release, started;
  const entered = new Promise(resolve => { started = resolve; });
  const context = vm.createContext({
    document: { createElement() { return box; } },
    $: id => id === 'ns-val' ? input : null,
    confirm: () => true, modalOpen: () => true, H: () => ({}),
    fetch: async u => { requests.push(u); return { ok: true }; },
    api: async (method, u) => { if (method === 'GET') return { api_key_set: true, configured: true }; requests.push(u); return { status: 'not_found' }; },
    OpenWarpEnzoicPairs: {checkCredentials: async (_, __, options) => {
      if (waitForResponse) await options.fetch('/provider', {});
      started(); await new Promise(resolve => { release = resolve; });
      if (!waitForResponse) await options.fetch('/provider', {});
      return {status:'found'};
    }},
    OpenWarpSecretHealth: Object.fromEntries(['checkPassword', 'checkEnzoicPassword', 'checkEmailExposure'].map(name => [name, async (_, options) => {
      if (waitForResponse) await options.fetch('/provider', {});
      started(); await new Promise(resolve => { release = resolve; });
      if (!waitForResponse) await options.fetch('/provider', {});
      return { status: 'found', count: 3, breaches: ['sensitive result'] };
    }]))
  });
  vm.runInContext('let EMERGENCY=false,PROJECT_EMERGENCY=false,SECRET_EPOCH=0,HEALTH_GENERATION=0;' + mount + ';mountSecretHealth();', context);
  const run = code => vm.runInContext(code, context);
  return { buttons, output, requests, entered, release: () => release(), run, ready: async () => { details.toggle(); await Promise.resolve(); await Promise.resolve(); } };
}

for (const flag of ['EMERGENCY', 'PROJECT_EMERGENCY']) {
  test(`${flag} blocks cached health buttons before disclosure`, async () => {
    const h = harness(); await h.ready(); h.run(`${flag}=true`);
    for (const kind of ['password', 'email', 'enzoic', 'leakcheck', 'pair']) await h.buttons[kind].onclick();
    assert.deepEqual(h.requests, []);
    assert.equal(h.output.textContent, '');
  });
}
for (const kind of ['password', 'enzoic', 'leakcheck', 'pair']) {
  test(`${kind} rechecks lockdown after asynchronous hashing`, async () => {
    const h = harness(); await h.ready(); const pending = h.buttons[kind].onclick(); await h.entered;
    h.run('PROJECT_EMERGENCY=true;SECRET_EPOCH++;'); h.release(); await pending;
    assert.deepEqual(h.requests, []);
    assert.equal(h.output.textContent, 'Checking...');
  });
  test(`${kind} rejects an old editor after lockdown is restored`, async () => {
    const h = harness(); await h.ready(); h.run('SECRET_EPOCH++;');
    await h.buttons[kind].onclick();
    assert.deepEqual(h.requests, []);
    assert.equal(h.output.textContent, '');
  });
  test(`${kind} discards a response when lockdown starts in flight`, async () => {
    const h = harness(); await h.ready(); const pending = h.buttons[kind].onclick(); await h.entered;
    h.release(); h.run('EMERGENCY=true;SECRET_EPOCH++;'); await pending;
    assert.doesNotMatch(h.output.textContent, /sensitive result|Found in/);
  });
}
