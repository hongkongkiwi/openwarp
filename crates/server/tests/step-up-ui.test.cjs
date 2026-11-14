'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

// Reuse the full console's DOM fixture without registering its product tests.
const fixturePath = path.join(__dirname, 'product-ui.test.cjs');
const fixtureSource = fs.readFileSync(fixturePath, 'utf8');
const testStart = fixtureSource.indexOf("\ntest('the full inline console");
assert.ok(testStart > 0, 'existing console fixture is available');
const fixture = new Module(fixturePath, module);
fixture.filename = fixturePath;
fixture.paths = module.paths;
fixture._compile(fixtureSource.slice(0, testStart) + '\nmodule.exports = { consoleUI, noClientPersistence };', fixturePath);
const { consoleUI, noClientPersistence } = fixture.exports;

const target = '/api/orgs/org-a/settings';
const info = { error: 'step-up verification required', step_up_required: true, risk: 'very_risky', totp_required: true, email_required: true };
function response(status, body) {
  return { status, ok: status >= 200 && status < 300, text: async () => JSON.stringify(body), json: async () => JSON.parse(JSON.stringify(body)) };
}
async function harness({ rejectReplay = false, holdVerify = false } = {}) {
  const ui = await consoleUI({ requireProducts: false });
  ui.run("AUTH_READY=true;T='fixture-session';APP={id:'app-a'};ENV={id:'env-a',mode:'sse'};");
  const bridge = ui.run('globalThis.stepFixture={}');
  const requests = [], issued = [], spent = new Set();
  let releaseVerify;
  bridge.fetch = async (url, options = {}) => {
    const request = { url, method: options.method || 'GET', headers: { ...options.headers }, body: options.body === undefined ? undefined : JSON.parse(options.body) };
    requests.push(request);
    if (url === '/api/auth/step-up/start') {
      assert.deepEqual(request.body, { risk: 'very_risky' });
      const challenge = 'fixture-challenge-' + issued.length;
      issued.push(challenge);
      return response(200, { challenge, risk: 'very_risky', methods: ['totp', 'email'], email_sent: true });
    }
    if (url === '/api/auth/step-up/verify') {
      assert.ok(issued.includes(request.body.challenge), 'verify uses the issued challenge');
      assert.equal(request.body.email_code, '123456');
      assert.equal(request.body.totp, '654321');
      if (holdVerify) await new Promise(resolve => { releaseVerify = resolve; });
      return response(200, { token: 'fixture-grant-' + request.body.challenge, risk: 'very_risky', expires_in: 300 });
    }
    if (url === target || url === '/api/envs/env-a/secrets') {
      const grant = Object.entries(request.headers).find(([key]) => key.toLowerCase() === 'x-openwarp-step-up')?.[1];
      if (!grant || rejectReplay) return response(428, info);
      assert.ok(grant.startsWith('fixture-grant-fixture-challenge-'), 'only the verified one-shot grant is replayed');
      assert.ok(!spent.has(grant), 'one-shot grant cannot be reused by another request');
      spent.add(grant);
      return response(200, { ok: true, deployed: 1 });
    }
    if (url === '/api/me') return response(200, { id: 'fixture-user' });
    throw new Error('Unexpected step-up fixture request: ' + request.method + ' ' + url);
  };
  ui.run('fetch=(...args)=>stepFixture.fetch(...args)');
  return { ui, requests, issued, spent, releaseVerify: () => { assert.ok(releaseVerify, 'verification is in flight'); releaseVerify(); } };
}
function start(h, code = `api('PUT','${target}',{reuse_check:false})`) {
  return Promise.resolve(h.ui.run(code)).then(value => ({ value }), error => ({ error }));
}
async function dialog(h) {
  await h.ui.settle();
  assert.ok(actions(h).length > 0, 'the real API helper reached the fixture 428 response');
  assert.ok(h.ui.el('modalwrap').classList.contains('show'), '428 must open an interactive verification dialog');
  assert.equal(h.requests.filter(r => r.url === '/api/auth/step-up/start').length, h.issued.length);
  h.ui.field(/email/i).value = '123456';
  h.ui.field(/authenticator|totp|recovery/i).value = '654321';
}
async function verify(h) { await h.ui.click(h.ui.button(h.ui.el('modal'), /verify|confirm|continue/i)); }
async function finished(operation) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('challenged request remained pending after dialog completion')), 1000); })]); }
  finally { clearTimeout(timer); }
}
function actions(h) { return h.requests.filter(r => r.url === target || r.url === '/api/envs/env-a/secrets'); }

for (const helper of ['api', 'apiRaw']) {
  test(`${helper} replays a 428 once with the original request and a fresh one-shot grant`, async () => {
    const h = await harness();
    for (let i = 0; i < 2; i++) {
      const operation = start(h, `${helper}('PUT','${target}',{reuse_check:false})`);
      await dialog(h); await verify(h);
      const result = await finished(operation);
      assert.ok(!result.error, result.error?.message);
      assert.equal(helper === 'api' ? result.value.ok : result.value.body.ok, true);
    }
    await h.ui.run(`${helper}('GET','/api/me')`);
    const read = h.requests.at(-1);
    assert.equal(read.url, '/api/me');
    assert.ok(!Object.keys(read.headers).some(key => key.toLowerCase() === 'x-openwarp-step-up'), 'ordinary requests never inherit a previous grant');
    assert.equal(h.issued.length, 2, 'a subsequent action obtains new proof, not a cached grant');
    assert.equal(h.spent.size, 2);
    assert.equal(actions(h).length, 4, 'each action has one original and one replay');
    for (const call of actions(h)) {
      assert.equal(call.method, 'PUT'); assert.deepEqual(call.body, { reuse_check: false });
      assert.equal(call.headers.Authorization, 'Bearer fixture-session');
    }
    noClientPersistence(h.ui);
  });
}

test('another 428 on replay fails without an automatic verification loop', async () => {
  const h = await harness({ rejectReplay: true }); const operation = start(h);
  await dialog(h); await verify(h);
  assert.ok((await finished(operation)).error, 'a rejected grant must not appear successful');
  assert.equal(actions(h).length, 2); assert.equal(h.issued.length, 1);
});

for (const dismiss of ['cancel', 'escape', 'backdrop']) {
  test(`${dismiss} dismisses verification and settles the request without replay`, async () => {
    const h = await harness(); const operation = start(h); await dialog(h);
    if (dismiss === 'cancel') await h.ui.click(h.ui.button(h.ui.el('modal'), /cancel/i));
    else if (dismiss === 'escape') h.ui.document.dispatchEvent({ type: 'keydown', key: 'Escape' });
    else h.ui.el('modalwrap').dispatchEvent({ type: 'click', target: h.ui.el('modalwrap') });
    assert.ok((await finished(operation)).error, 'dismissal cancels the action');
    assert.equal(actions(h).length, 1); assert.equal(h.requests.filter(r => r.url.endsWith('/verify')).length, 0);
  });
}

for (const change of ["T='replacement-session'", "ORG='org-b'", 'sessionEnded()', 'applyEmergency(true,false)', 'applyEmergency(false,true)']) {
  test(`verification cannot replay after context changes: ${change}`, async () => {
    const h = await harness({ holdVerify: true }); const operation = start(h); await dialog(h);
    const verifying = verify(h); await h.ui.settle();
    assert.equal(h.requests.filter(r => r.url.endsWith('/verify')).length, 1, 'proof submission is pending');
    h.ui.run(change); h.releaseVerify(); await verifying;
    assert.ok((await finished(operation)).error, 'old request is cancelled even if verification later succeeds');
    assert.equal(actions(h).length, 1, 'old secret/settings payload never crosses the changed context');
    noClientPersistence(h.ui);
  });
}

test('a replaced pending verification does not leave either caller hanging', async () => {
  const h = await harness(); const first = start(h); await dialog(h);
  const second = start(h); await h.ui.settle();
  await h.ui.click(h.ui.button(h.ui.el('modal'), /cancel/i)); await h.ui.settle();
  if (h.ui.el('modalwrap').classList.contains('show')) await h.ui.click(h.ui.button(h.ui.el('modal'), /cancel/i));
  const results = await Promise.all([finished(first), finished(second)]);
  assert.ok(results.every(r => r.error), 'both cancelled actions settle as errors');
  assert.equal(actions(h).length, 2, 'neither request runs without independent proof');
});

test('deploy confirmation never clears a newer secret draft', async () => {
  const h = await harness();
  h.ui.run("DRAFTS={'env-a':{fixture:{key:'FIXTURE',value:'dummy-before',path:'/',type:'secret'}}};VIEW='apps'");
  const operation = start(h, 'deployStage()'); await dialog(h);
  h.ui.run("DRAFTS['env-a'].fixture.value='dummy-after'");
  await verify(h); await finished(operation);
  assert.equal(actions(h)[1].body.secrets[0].value, 'dummy-before', 'retry preserves the submitted snapshot');
  assert.equal(h.ui.run("DRAFTS['env-a'].fixture.value"), 'dummy-after', 'editing while proof is pending does not lose the new draft');
  noClientPersistence(h.ui);
});
