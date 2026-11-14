'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const fixturePath = path.join(__dirname, 'product-ui.test.cjs');
const fixtureSource = fs.readFileSync(fixturePath, 'utf8');
const testStart = fixtureSource.indexOf("\ntest('the full inline console");
assert.ok(testStart > 0, 'existing console fixture is available');
const fixture = new Module(fixturePath, module);
fixture.filename = fixturePath;
fixture.paths = module.paths;
fixture._compile(fixtureSource.slice(0, testStart) + '\nmodule.exports = { consoleUI, noClientPersistence };', fixturePath);
const { consoleUI, noClientPersistence } = fixture.exports;

const target = '/api/orgs/org-a/change-requests';
const draftTitle = 'Unsubmitted release draft';
const draftChanges = '[{"env_id":"env-a","secrets":[{"key":"FIXTURE","value":"dummy-draft"}]}]';
const required = { error: 'verification required', step_up_required: true, risk: 'very_risky', email_required: true };
function response(status, body) {
  return { status, ok: status >= 200 && status < 300, text: async () => typeof body === 'string' ? body : JSON.stringify(body) };
}
async function harness(startResponse, holdStart = false) {
  const ui = await consoleUI({ requireProducts: false });
  ui.run("AUTH_READY=true;T='fixture-session';APP={id:'app-a'};ENV={id:'env-a',mode:'sse'};");
  await ui.invoke('productRequestModal()');
  ui.field(/title/i).value = draftTitle;
  const changes = ui.field(/changes|json/i);
  changes.value = draftChanges; changes.focus();
  const bridge = ui.run('globalThis.pr32StartFixture={}');
  const requests = [];
  let releaseStart;
  bridge.fetch = async (url, options = {}) => {
    const request = { url, method: options.method, headers: { ...options.headers }, body: options.body === undefined ? undefined : JSON.parse(options.body) };
    requests.push(request);
    if (url === target) return requests.filter(r => r.url === target).length === 1 ? response(428, required) : response(200, { ok: true });
    assert.equal(url, '/api/auth/step-up/start', 'start failure never submits proof or another action');
    assert.deepEqual(request.body, { risk: 'very_risky' });
    if (holdStart) await new Promise(resolve => { releaseStart = resolve; });
    return startResponse;
  };
  ui.run('fetch=(...args)=>pr32StartFixture.fetch(...args)');
  return { ui, changes, requests, releaseStart: () => { assert.ok(releaseStart, 'start request is pending'); releaseStart(); } };
}
function start(h, helper) {
  return Promise.resolve(h.ui.run(`${helper}('POST','${target}',{title:$('product-title').value,changes:JSON.parse($('product-changes').value)})`))
    .then(value => ({ value }), error => ({ error }));
}
async function finished(operation) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('action remained pending after step-up start settled')), 1000); })]); }
  finally { clearTimeout(timer); }
}
function assertDraft(h) {
  assert.ok(h.ui.el('modalwrap').classList.contains('show'), 'the original action dialog remains open');
  assert.equal(h.ui.field(/title/i).value, draftTitle, 'the original title draft survives');
  assert.equal(h.ui.field(/changes|json/i).value, draftChanges, 'the original JSON draft survives');
  assert.equal(h.ui.document.activeElement, h.changes, 'focus returns to the original draft field');
  assert.equal(h.ui.el('modal').getAttribute('role'), 'dialog');
  assert.equal(h.ui.el('modal').getAttribute('aria-label'), 'Change request');
  noClientPersistence(h.ui);
}

for (const helper of ['api', 'apiRaw']) {
  for (const [name, reply] of [
    ['HTTP 500', () => response(500, { error: 'fixture mail service unavailable' })],
    ['malformed JSON', () => response(200, '{')],
  ]) {
    test(`${helper} preserves the open action draft and focus when step-up start returns ${name}`, async () => {
      const h = await harness(reply());
      const result = await finished(start(h, helper));
      assert.ok(result.error, 'a failed start settles the action as an error');
      assert.equal(h.requests.filter(r => r.url === target).length, 1, 'start failure must not replay the action');
      assert.equal(h.requests.filter(r => r.url === '/api/auth/step-up/start').length, 1);
      assertDraft(h);
    });
  }

  test(`${helper} preserves the action dialog when step-up start says not_required`, async () => {
    const h = await harness(response(200, { not_required: true }));
    const result = await finished(start(h, helper));
    assert.ok(!result.error, result.error?.message);
    assert.equal(helper === 'api' ? result.value.ok : result.value.body.ok, true);
    const actions = h.requests.filter(r => r.url === target);
    assert.equal(actions.length, 2, 'not_required permits exactly one replay');
    assert.deepEqual(actions[1].body, actions[0].body, 'the retry uses the submitted draft snapshot');
    assert.ok(!Object.keys(actions[1].headers).some(key => key.toLowerCase() === 'x-openwarp-step-up'), 'not_required does not invent proof');
    assertDraft(h);
  });
}

test('a session ending while step-up start is pending cancels without restoring the old action draft', async () => {
  const h = await harness(response(200, { not_required: true }), true);
  const operation = start(h, 'api'); await h.ui.settle();
  assert.equal(h.requests.filter(r => r.url === '/api/auth/step-up/start').length, 1);
  h.ui.run('sessionEnded()'); h.releaseStart();
  assert.ok((await finished(operation)).error, 'the stale action settles as cancelled');
  assert.equal(h.requests.filter(r => r.url === target).length, 1, 'session change prevents replay');
  assert.ok(!h.ui.el('modalwrap').classList.contains('show'), 'a cleared session never restores its old action dialog');
  assert.equal(h.ui.el('modal').innerHTML, '', 'the old draft remains cleared after the late start response');
  noClientPersistence(h.ui);
});

for (const helper of ['api', 'apiRaw']) {
  test(`${helper} clears the old action dialog immediately when switchOrg races a pending step-up start`, async () => {
    const h = await harness(response(200, { challenge: 'old-workspace-challenge', methods: ['email'], email_sent: true }), true);
    const bridge = h.ui.run('pr32StartFixture');
    const originalFetch = bridge.fetch;
    let releaseEmergency, emergencyStarted = false;
    const emergency = new Promise(resolve => { releaseEmergency = resolve; });
    bridge.fetch = async (url, options) => {
      if (url === '/api/orgs/org-b/emergency') {
        emergencyStarted = true;
        await emergency;
        return response(200, { locked: false });
      }
      if (url === '/api/orgs/org-b/apps') return response(200, []);
      return originalFetch(url, options);
    };
    const operation = start(h, helper); await h.ui.settle();
    assert.equal(h.requests.filter(r => r.url === '/api/auth/step-up/start').length, 1, 'the old workspace start request is in flight');
    assertDraft(h);
    let switching;
    const assertCleared = () => {
      assert.ok(!h.ui.el('modalwrap').classList.contains('show'), 'switchOrg must close the old action dialog before the new workspace refresh completes');
      assert.equal(h.ui.el('modal').querySelector('#product-title'), null, 'the old workspace title field is removed');
      assert.equal(h.ui.el('modal').querySelector('#product-changes'), null, 'the old workspace JSON draft field is removed');
      assert.equal(h.ui.run('PRODUCT_DIALOG'), null, 'the old action dialog context is discarded');
      assert.equal(h.ui.run('STEP_UP'), null, 'the old verification is cancelled immediately');
    };
    try {
      switching = Promise.resolve(h.ui.run("switchOrg('org-b')")).then(value => ({ value }), error => ({ error }));
      await h.ui.settle();
      assert.ok(emergencyStarted, 'the real switchOrg is waiting for the new workspace emergency response');
      assert.equal(h.ui.run('ORG'), 'org-b');
      assertCleared();
      assert.ok((await finished(operation)).error, 'workspace switching settles the old action without waiting for its start response');
      h.releaseStart(); await h.ui.settle();
      assertCleared();
      assert.equal(h.requests.filter(r => r.url === target).length, 1, 'the late start response never replays the old workspace payload');
      releaseEmergency();
      const switched = await finished(switching);
      assert.ok(!switched.error, switched.error?.message);
      assertCleared();
      noClientPersistence(h.ui);
    } finally {
      h.releaseStart(); releaseEmergency();
      await finished(operation);
      if (switching) await finished(switching);
    }
  });
}
