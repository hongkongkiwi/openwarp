'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
const html = source.match(/r##"([\s\S]*)"##;/)?.[1];
assert.ok(html, 'embedded console HTML is available');
const script = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
  .filter(([, attrs]) => !/\bsrc\s*=/.test(attrs)).map(([, , body]) => body).join('\n');

// Evaluate the shipped functions unchanged, without the console's startup or unrelated screens.
function shippedFunction(name) {
  const declarations = [...script.matchAll(/^(?:async )?function (\w+)\(/gm)];
  const index = declarations.findIndex(match => match[1] === name);
  assert.notEqual(index, -1, `shipped function ${name} exists`);
  return script.slice(declarations[index].index, declarations[index + 1]?.index ?? script.length);
}

function invitationConsole({ bearer = 'fixture-social-session', cookie = false, denied = false } = {}) {
  const calls = [], errors = [], navigations = [];
  const session = new Map();
  const elements = new Map();
  const document = { getElementById(id) {
    if (!elements.has(id)) elements.set(id, { style: {}, innerHTML: '', textContent: '', value: '' });
    return elements.get(id);
  } };
  const context = vm.createContext({
    document, console,
    sessionStorage: { getItem: key => session.get(key) ?? null, setItem: (key, value) => session.set(key, String(value)), removeItem: key => session.delete(key) },
    location: { pathname: '/', hash: '' }, history: { replaceState() {} },
    toast: message => errors.push(message), modal: () => assert.fail('existing account must not receive a new recovery kit'),
    // The shipped functions under test call the console's i18n and emergency
    // helpers; standalone evaluation only needs their side effects.
    owText: (el, text) => { el.textContent = text; },
    refreshEmergency: async () => {}, setInterval: () => 1, clearInterval() {},
    nav: async page => { navigations.push(page); },
    fetch: async (url, options) => {
      const call = { url, method: options.method, authorization: options.headers.Authorization, body: options.body && JSON.parse(options.body) };
      calls.push(call);
      let status = 200, body;
      if (url === '/api/auth/invite?token=fixture-invite') body = { existing_account: true, org_id: 'joined-org', org_name: 'Invited workspace', email: 'invitee@test.invalid', role: 'developer', expires_at: 2000000000 };
      else if (url === '/api/auth/providers') body = { workspace_creation_open: false };
      else if (!cookie && call.authorization !== 'Bearer fixture-social-session') { status = 401; body = { error: 'missing account session' }; }
      else if (url === '/api/me') body = { id: 'invitee', email: 'invitee@test.invalid' };
      else if (url === '/api/auth/accept-invite' && call.method === 'POST') {
        status = denied ? 403 : 200;
        body = denied ? { error: 'inviter no longer authorized' } : { user_id: 'invitee', org_id: 'joined-org', role: 'developer' };
      }
      else if (url === '/api/orgs') body = [{ id: 'old-org', name: 'Existing workspace', role: 'owner' }, { id: 'joined-org', name: 'Invited workspace', role: 'developer' }];
      else assert.fail(`unexpected request ${call.method} ${url}`);
      return { ok: status === 200, status, text: async () => JSON.stringify(body) };
    },
  });
  const headers = script.match(/^const H=.*$/m)?.[0];
  assert.ok(headers, 'evaluate the shipped request header builder');
    vm.runInContext(`let T=${JSON.stringify(bearer)}, INVITE='', INVITE_META=null, PENDING_ORG=null, E2E_KIT='', ORG='', APP=null, ENV=null, ME=null, MY_PUBKEY='', MY_UID='', CREATION_OPEN=true, EMERGENCY=false, PROJECT_EMERGENCY=false, EMERGENCY_POLL=null, AUTH_READY=false;
    const $=id=>document.getElementById(id);\n${headers}\n` +
    ['api', 'esc', 'showInvite', 'acceptInvite', 'enterApp'].map(shippedFunction).join('\n'), context);
  return { calls, errors, navigations, session, elements, run: code => vm.runInContext(code, context) };
}

for (const mode of ['bearer-only social session', 'HttpOnly cookie session']) {
  test(`existing-account invitation consent keeps ${mode} authenticated through enterApp`, async () => {
    const ui = invitationConsole(mode.startsWith('HttpOnly') ? { bearer: '', cookie: true } : {});
    await ui.run("showInvite('fixture-invite')");
    assert.equal(ui.calls.filter(call => call.method === 'POST').length, 0, 'preview must not silently accept the invitation');
    assert.match(ui.elements.get('authform').innerHTML, /Join workspace/);
    assert.equal(ui.session.get('ow_pending_invite'), 'fixture-invite');

    await ui.run('acceptInvite()');

    const acceptance = ui.calls.find(call => call.method === 'POST');
    assert.equal(acceptance.url, '/api/auth/accept-invite');
    assert.deepEqual(acceptance.body, { token: 'fixture-invite' });
    assert.deepEqual(ui.errors, [], 'the authenticated application bootstrap must not lose its account session after consent');
    assert.deepEqual(ui.navigations, ['apps'], 'consent must finish entering the application');
    assert.equal(ui.elements.get('orgs').value, 'joined-org', 'select the newly joined workspace instead of an earlier membership');
    assert.equal(ui.session.has('ow_pending_invite'), false);
    if (mode.startsWith('bearer')) {
      const afterConsent = ui.calls.slice(ui.calls.indexOf(acceptance) + 1).filter(call => ['/api/me', '/api/orgs'].includes(call.url));
      assert.equal(afterConsent.length, 2);
      for (const call of afterConsent) assert.equal(call.authorization, 'Bearer fixture-social-session', 'subsequent protected requests retain the existing bearer session');
    }
  });
}

test('denied invitation consent leaves the pending invitation and does not enter the app', async () => {
  const ui = invitationConsole({ denied: true });
  await ui.run("showInvite('fixture-invite')");
  await ui.run('acceptInvite()');
  assert.deepEqual(ui.errors, ['inviter no longer authorized']);
  assert.deepEqual(ui.navigations, []);
  assert.equal(ui.session.get('ow_pending_invite'), 'fixture-invite');
  assert.equal(ui.calls.filter(call => call.url === '/api/orgs').length, 0);
});
