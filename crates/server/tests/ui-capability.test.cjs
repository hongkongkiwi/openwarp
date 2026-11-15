'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
const settings = source.slice(source.indexOf('async function renderSettings()'), source.indexOf('\nfunction oidcPreset()'));
assert.ok(settings.startsWith('async function renderSettings()') && settings.endsWith('}'), 'settings renderer is extractable');

async function render(compiled, granted, locked = false, org = 'org-a') {
  const elements = { view: {}, pagetitle: {}, crumb: {} }, loads = [];
  const context = vm.createContext({
    ORG: org, VIEW: 'settings', PRODUCT_RENDER: 0, AUTH_READY: true, EMERGENCY: false,
    PROJECT_EMERGENCY: false, EMERGENCY_OWNER: false, APP: null, EDITION: null, ME: null,
    $: id => elements[id], owText() {}, owDataText() {}, currentOrg: () => ({ locked }),
    api: async (_method, url) => url.endsWith('/features') ? { compiled, granted } : url === '/api/orgs' ? [] : null,
    isEnterprise: () => false, themePref: () => 'system', esc: String, jsq: String,
    loadSshCAs: () => loads.push('ssh-ca'), renderPki: () => loads.push('pki'),
  });
  await vm.runInContext(settings + '\nrenderSettings()', context);
  return { html: elements.view.innerHTML, loads };
}

for (const [name, id] of [['pki', 'pki-body'], ['ssh-ca', 'ssh-ca-list']]) {
  test(name + ' requires both compilation and a workspace grant for its card and load', async () => {
    for (const compiled of [[], [name]]) for (const granted of [[], [name]]) {
      const result = await render(compiled, granted);
      const enabled = compiled.includes(name) && granted.includes(name);
      assert.equal(result.html.includes('id="' + id + '"'), enabled, 'card: ' + JSON.stringify({ compiled, granted }));
      assert.equal(result.loads.includes(name), enabled, 'load: ' + JSON.stringify({ compiled, granted }));
      assert.equal(result.html.includes('A workspace feature grant is required'), compiled.includes(name) && !granted.includes(name));
    }
    for (const result of [await render([name], [name], true), await render([name], [name], false, '')]) {
      assert.ok(!result.html.includes('id="' + id + '"'));
      assert.ok(!result.loads.includes(name));
    }
  });
}

test('mixed grants load only enabled features and share one grant note', async () => {
  const result = await render(['pki', 'ssh-ca'], ['pki']);
  assert.ok(result.html.includes('id="pki-body"'));
  assert.ok(!result.html.includes('id="ssh-ca-list"'));
  assert.deepEqual(result.loads, ['pki']);
  assert.equal(result.html.match(/A workspace feature grant is required/g)?.length, 1);
  const ungranted = await render(['pki', 'ssh-ca'], []);
  assert.equal(ungranted.html.match(/A workspace feature grant is required/g)?.length, 1);
});

test('toast stack stays bounded at the viewport top and scrolls to the newest message', () => {
  const rule = source.match(/#toasts\{([^}]*)\}/)?.[1];
  assert.ok(rule, 'toast container style exists');
  assert.match(rule, /position:fixed/);
  assert.match(rule, /top:18px/);
  assert.match(rule, /max-height:/);
  assert.match(rule, /overflow-y:auto/);
  assert.match(source, /appendChild\(el\);\s*\$\('toasts'\)\.scrollTop=\$\('toasts'\)\.scrollHeight/);
  assert.match(source, /setTimeout\(\(\)=>\{el\.style\.opacity='0';setTimeout\(\(\)=>el\.remove\(\),320\)\},3000\)/);
});
