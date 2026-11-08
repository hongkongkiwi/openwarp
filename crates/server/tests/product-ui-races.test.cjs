'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

// Reuse the DOM/HTTP fixture without registering the original suite's tests.
const fixturePath = path.join(__dirname, 'product-ui.test.cjs');
const fixtureSource = fs.readFileSync(fixturePath, 'utf8');
const testStart = fixtureSource.indexOf("\ntest('the full inline console");
assert.ok(testStart > 0, 'existing product UI fixture is available');
const fixture = new Module(fixturePath, module);
fixture.filename = fixturePath;
fixture.paths = module.paths;
fixture._compile(fixtureSource.slice(0, testStart) + '\nmodule.exports = { consoleUI, transitForm, noClientPersistence, visible };', fixturePath);
const { consoleUI, transitForm, noClientPersistence, visible } = fixture.exports;

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
function delayedDecrypts() {
  const pending = [];
  return {
    pending,
    async intercept(call) {
      if (call.method !== 'POST' || !call.url.endsWith('/decrypt')) return null;
      const response = deferred(); pending.push({ call, response });
      return response.promise;
    },
    resolve(index, plaintext) { pending[index].response.resolve({ body: { plaintext, version: 2 } }); },
  };
}
function output(ui) { return ui.el('tr-output').textContent; }
function start(ui) {
  const operation = ui.run('runProductTransit()');
  return { operation, started: ui.settle() };
}

test('remaining transit action changes invalidate pending plaintext even after returning to decrypt', async () => {
  const delayed = delayedDecrypts(); const ui = await consoleUI({ intercept: delayed.intercept });
  await ui.access(); await transitForm(ui, 'decrypt');
  const first = start(ui); await first.started;
  assert.equal(delayed.pending.length, 1, 'the first decrypt request is pending');
  await ui.change(ui.field(/action|operation/i), 'encrypt');
  assert.equal(output(ui), ''); assert.equal(ui.field(/input|plaintext|ciphertext/i).value, '');
  await ui.change(ui.field(/action|operation/i), 'decrypt');
  delayed.resolve(0, 'c3RhbGUtcGxhaW50ZXh0'); await first.operation; await ui.settle();
  assert.equal(output(ui), '', 'returning to decrypt must not revive the previous operation result');
  noClientPersistence(ui);
});

test('remaining out-of-order transit responses cannot replace the newest decrypt result', async () => {
  const delayed = delayedDecrypts(); const ui = await consoleUI({ intercept: delayed.intercept });
  await ui.access(); await transitForm(ui, 'decrypt');
  ui.field(/input|plaintext|ciphertext/i).value = 'owt1:request-A';
  const first = start(ui); await first.started;
  ui.field(/input|plaintext|ciphertext/i).value = 'owt1:request-B';
  const second = start(ui); await second.started;
  assert.equal(delayed.pending.length, 2, 'both decrypts reached the HTTP boundary');
  assert.deepEqual(delayed.pending.map(p => p.call.body.ciphertext), ['owt1:request-A', 'owt1:request-B']);
  delayed.resolve(1, 'bmV3ZXN0LXBsYWludGV4dA=='); await second.operation; await ui.settle();
  assert.equal(output(ui), 'bmV3ZXN0LXBsYWludGV4dA==', 'the latest request result is visible');
  delayed.resolve(0, 'b2xkZXItcGxhaW50ZXh0'); await first.operation; await ui.settle();
  assert.equal(output(ui), 'bmV3ZXN0LXBsYWludGV4dA==', 'the older request cannot overwrite the latest result');
  noClientPersistence(ui);
});

test('remaining a dismissed transit response cannot populate a replacement dialog', async () => {
  const delayed = delayedDecrypts(); const ui = await consoleUI({ intercept: delayed.intercept });
  await ui.access(); await transitForm(ui, 'decrypt');
  const first = start(ui); await first.started;
  await ui.click(ui.button(ui.el('modal'), /^Close$/i));
  await transitForm(ui, 'decrypt');
  const before = ui.el('modal').innerHTML;
  delayed.resolve(0, 'ZGlzbWlzc2VkLXBsYWludGV4dA=='); await first.operation; await ui.settle();
  assert.equal(output(ui), ''); assert.equal(ui.el('modal').innerHTML, before);
  noClientPersistence(ui);
});

for (const pending of [false, true]) {
  test(`remaining workspace switch clears the old transit dialog (${pending ? 'pending' : 'completed'} decrypt)`, async () => {
    const delayed = delayedDecrypts(); const ui = await consoleUI({ intercept: delayed.intercept });
    await ui.access(); await transitForm(ui, 'decrypt');
    const input = ui.field(/input|plaintext|ciphertext/i); input.value = 'owt1:workspace-A-ciphertext';
    const first = start(ui); await first.started;
    if (!pending) {
      delayed.resolve(0, 'd29ya3NwYWNlLUEtcGxhaW50ZXh0'); await first.operation; await ui.settle();
      assert.equal(output(ui), 'd29ya3NwYWNlLUEtcGxhaW50ZXh0');
    }
    await ui.change(ui.el('orgs'), 'org-b');
    assert.equal(ui.run('ORG'), 'org-b', 'the real workspace selector changed the active workspace');
    if (pending) { delayed.resolve(0, 'd29ya3NwYWNlLUEtcGxhaW50ZXh0'); await first.operation; await ui.settle(); }
    const modal = ui.el('modal');
    assert.ok(!visible(modal) || !ui.el('modalwrap').classList.contains('show'), 'workspace A dialog must not remain visible in workspace B');
    assert.ok(!modal.textContent.includes('d29ya3NwYWNlLUEtcGxhaW50ZXh0'), 'old plaintext must be removed, not merely hidden');
    assert.ok(!modal.querySelectorAll('textarea,input').some(el => el.value.includes('workspace-A-ciphertext')), 'old operation input must be cleared');
    noClientPersistence(ui);
  });
}
