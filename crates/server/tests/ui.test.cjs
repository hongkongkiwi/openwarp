'use strict';

// Run with node --test crates/server/tests/ui.test.cjs. No server or browser is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
const html = source.match(/r##"([\s\S]*)"##;/)?.[1];
assert.ok(html, 'the embedded console HTML must be extractable');
const script = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
  .filter(([, attrs]) => !/\bsrc\s*=/.test(attrs)).map(([, , body]) => body).join('\n');
assert.ok(script.trim(), 'the console must contain executable inline JavaScript');
const css = html.match(/<style>([\s\S]*?)<\/style>/i)[1].split('@media')[0];
const decode = value => String(value).replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos|#39);/gi,
  (_, code) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[code] ??
    String.fromCodePoint(code[1].toLowerCase() === 'x' ? parseInt(code.slice(2), 16) : Number(code.slice(1)))));

// This shim models the DOM APIs used by the inline console, not layout or browser tab order.
class Element {
  constructor(tagName, document, attrs = {}) {
    this.tagName = tagName.toUpperCase();
    this.ownerDocument = document;
    this.attributes = { ...attrs };
    this.children = [];
    this.parentElement = null;
    this.listeners = {};
    this.style = {};
    this.dataset = new Proxy({}, {
      get: (_, key) => this.getAttribute('data-' + String(key).replace(/[A-Z]/g, c => '-' + c.toLowerCase())),
      set: (_, key, value) => { this.setAttribute('data-' + String(key).replace(/[A-Z]/g, c => '-' + c.toLowerCase()), value); return true; },
    });
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(n => !names.includes(n)).join(' '); },
      toggle: (name, force) => {
        const add = force === undefined ? !this.classList.contains(name) : force;
        this.classList[add ? 'add' : 'remove'](name);
        return add;
      },
    };
    for (const decl of (attrs.style || '').split(';')) {
      const at = decl.indexOf(':');
      if (at > 0) this.style[decl.slice(0, at).trim()] = decl.slice(at + 1).trim();
    }
  }
  get id() { return this.getAttribute('id') || ''; }
  get className() { return this.getAttribute('class') || ''; }
  set className(value) { this.setAttribute('class', value); }
  get hidden() { return this.hasAttribute('hidden'); }
  set hidden(value) { value ? this.setAttribute('hidden', '') : this.removeAttribute('hidden'); }
  get checked() { return this._checked ?? this.hasAttribute('checked'); }
  set checked(value) { this._checked = Boolean(value); }
  get disabled() { return this.hasAttribute('disabled'); }
  set disabled(value) { value ? this.setAttribute('disabled', '') : this.removeAttribute('disabled'); }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.tagName === 'TEXTAREA') return this.textContent;
    if (this.tagName === 'SELECT') {
      const options = this.querySelectorAll('option');
      const option = options.find(o => o.hasAttribute('selected')) || options[0];
      return option ? option.getAttribute('value') ?? option.textContent : '';
    }
    return this.getAttribute('value') || '';
  }
  set value(value) { this._value = String(value); }
  get textContent() { return this.children.map(c => typeof c === 'string' ? c : c.textContent).join(''); }
  set textContent(value) { this.children = [String(value)]; }
  get innerHTML() { return this.children.map(c => typeof c === 'string' ? c : c.outerHTML).join(''); }
  set innerHTML(value) { this.children = []; parse(String(value), this); }
  get outerHTML() {
    return `<${this.tagName.toLowerCase()}${Object.entries(this.attributes).map(([k, v]) => ` ${k}="${v}"`).join('')}>${this.innerHTML}</${this.tagName.toLowerCase()}>`;
  }
  getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  hasAttribute(name) { return Object.hasOwn(this.attributes, name); }
  appendChild(child) { this.children.push(child); child.parentElement = this; return child; }
  remove() { this.parentElement.children = this.parentElement.children.filter(c => c !== this); }
  contains(child) { return child === this || this.children.some(c => typeof c !== 'string' && c.contains(child)); }
  focus() { this.ownerDocument.activeElement = this; }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  dispatchEvent(event) {
    event.target ||= this;
    event.preventDefault ||= () => { event.defaultPrevented = true; };
    for (const listener of this.listeners[event.type] || []) listener(event);
    if (this.parentElement && event.bubbles !== false) this.parentElement.dispatchEvent(event);
    return !event.defaultPrevented;
  }
  matches(selector) {
    let excluded = false;
    selector = selector.replace(/:not\(([^)]+)\)/g, (_, inner) => { excluded ||= this.matches(inner); return ''; });
    if (excluded) return false;
    if (selector.includes(':disabled') && !this.disabled) return false;
    if (selector.includes(':enabled') && this.disabled) return false;
    selector = selector.replace(/:(disabled|enabled)/g, '');
    const tag = selector.match(/^[\w-]+/);
    if (tag && this.tagName !== tag[0].toUpperCase()) return false;
    for (const [, id] of selector.matchAll(/#([\w-]+)/g)) if (this.id !== id) return false;
    for (const [, name] of selector.matchAll(/\.([\w-]+)/g)) if (!this.classList.contains(name)) return false;
    for (const [, name, , value] of selector.matchAll(/\[([\w-]+)(?:\s*=\s*(["']?)(.*?)\2)?\]/g)) {
      if (!this.hasAttribute(name) || (value !== undefined && this.getAttribute(name) !== value)) return false;
    }
    return true;
  }
  querySelectorAll(selector) {
    const matches = element => selector.split(',').some(part => {
      const chain = part.trim().split(/\s+/);
      if (!element.matches(chain.pop())) return false;
      let parent = element.parentElement;
      while (chain.length) {
        const next = chain.pop();
        while (parent && !parent.matches(next)) parent = parent.parentElement;
        if (!parent) return false;
        parent = parent.parentElement;
      }
      return true;
    });
    const result = [];
    const walk = root => { for (const child of root.children) if (typeof child !== 'string') { if (matches(child)) result.push(child); walk(child); } };
    walk(this);
    return result;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  closest(selector) { return this.matches(selector) ? this : this.parentElement?.closest(selector) || null; }
}

function parse(markup, root) {
  const stack = [root];
  for (const token of markup.match(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g) || []) {
    if (/^<!/.test(token)) continue;
    if (/^<\//.test(token)) { if (stack.length > 1) stack.pop(); continue; }
    if (token[0] !== '<') { stack.at(-1).children.push(decode(token)); continue; }
    const [, tag, rest] = token.match(/^<([\w-]+)([\s\S]*?)\/?\s*>$/) || [];
    if (!tag) throw new Error('Unsupported HTML token: ' + token);
    const attrs = {};
    for (const [, name, , quoted, bare] of rest.matchAll(/([^\s=/>]+)(?:\s*=\s*(?:(["'])([\s\S]*?)\2|([^\s>]+)))?/g)) attrs[name] = decode(quoted ?? bare ?? '');
    const el = new Element(tag, root.ownerDocument, attrs);
    stack.at(-1).appendChild(el);
    if (!/^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/i.test(tag)) stack.push(el);
  }
}

function computedStyle(element) {
  const values = { display: element.hidden ? 'none' : 'block', visibility: 'visible' };
  const priorities = {};
  for (const [, selectors, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    for (const selector of selectors.split(',').map(s => s.trim())) {
      if (!element.matches(selector) || /[ >:+~]/.test(selector)) continue;
      const weight = (selector.match(/#/g) || []).length * 100 + (selector.match(/[.\[]/g) || []).length * 10;
      for (const decl of body.split(';')) {
        const at = decl.indexOf(':');
        if (at < 0) continue;
        const name = decl.slice(0, at).trim();
        const value = decl.slice(at + 1).trim();
        const priority = weight + (value.includes('!important') ? 10000 : 0);
        if ((priorities[name] ?? -1) <= priority) { priorities[name] = priority; values[name] = value.replace(/\s*!important/, ''); }
      }
    }
  }
  return { ...values, ...element.style };
}

function hidden(element) {
  for (let el = element; el; el = el.parentElement) {
    const style = computedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') return true;
  }
  return false;
}

const saved = { id: 'saved-secret', key: 'DATABASE_URL', value: 'fixture-original', path: '/service', type: 'secret', version: 2 };
const draft = { key: 'NEW_CONFIG', value: 'fixture-draft', path: '/draft', type: 'config', comment: '' };

async function consoleUI(secrets = [saved], reuse = [], opts = {}) {
  const document = new Element('document', null);
  document.ownerDocument = document;
  document.getElementById = id => document.querySelector('#' + id);
  document.createElement = tag => new Element(tag, document);
  parse(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<style>[\s\S]*?<\/style>/gi, ''), document);
  document.body = document.querySelector('body');
  document.activeElement = document.body;
  const calls = [], unexpected = [], confirmations = [], timers = [];
  const responses = {
    '/api/auth/providers': { google: false, github: false, signups: 'open' },
    '/api/instance': { instance_owner: false },
    '/api/me': { email: 'fixture@example.invalid' },
    '/api/orgs': [{ id: 'org-a', name: 'First org', role: 'admin' }, { id: 'org-b', name: 'Second org', role: 'admin' }],
    '/api/orgs/org-a/apps': [{ id: 'app-a', name: 'First app' }, { id: 'app-b', name: 'Second app' }],
    '/api/orgs/org-a/settings': { ip_allowlist: '', oidc_issuer: '', oidc_client_id: '', oidc_redirect_uri: '', oidc_client_secret_set: false, oidc_auto_provision: false, oidc_allowed_domains: '', audit_webhook: '' },
    '/api/orgs/org-a/saml': { configured: false },
    '/api/orgs/org-b/apps': [{ id: 'app-c', name: 'Other org app' }],
    '/api/apps/app-a/envs': [{ id: 'env-a', name: 'Development' }, { id: 'env-b', name: 'Production' }],
    '/api/apps/app-b/envs': [{ id: 'env-c', name: 'Other app env' }],
    '/api/apps/app-c/envs': [{ id: 'env-d', name: 'Other org env' }],
    '/api/envs/env-a/secrets': { secrets },
    '/api/envs/env-b/secrets': { secrets: [] },
    '/api/envs/env-c/secrets': { secrets: [] },
    '/api/envs/env-d/secrets': { secrets: [] },
    '/api/envs/env-a/folders': { folders: [] },
    '/api/envs/env-b/folders': { folders: [] },
    '/api/envs/env-c/folders': { folders: [] },
    '/api/envs/env-d/folders': { folders: [] },
    '/api/secrets/saved-secret/history': [],
    '/api/orgs/org-a/ssh/cas': [],
    '/api/ssh/cas/ca-ssh-1': { id: 'ca-ssh-1', name: 'ssh-ca', public_key: 'ssh-ed25519 AAAAC3Nza', fingerprint: 'SHA256:fixture', allow_forwarding: false, sshd: 'TrustedUserCAKeys /etc/ssh/openwarp/ca.pub', grants: [{ role: 'developer', principals: ['web-*'], max_ttl: 900 }] },
    '/api/ssh/cas/ca-ssh-1/certs': [{ id: 'ssh-cert-1', key_id: 'openwarp:ssh-cert-1', principal: 'web-1', serial: 7, revoked: 0, valid_before: 1800000000, cert_type: 'user' }],
    '/api/ssh/cas/ca-ssh-1/hosts': [{ id: 'host-1', hostname: 'db-1.internal', fingerprint: 'SHA256:hostkey' }],
  };
  const context = vm.createContext({
    document, console, URL, TextDecoder, TextEncoder,
    localStorage: { getItem: () => '', setItem() {}, removeItem() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    location: { origin: 'http://console.invalid', hash: '', pathname: '/', reload() {} },
    history: { replaceState() {} },
    setTimeout: fn => { timers.push(fn); return timers.length; }, clearTimeout() {},
    requestAnimationFrame: fn => { timers.push(fn); return timers.length; },
    getComputedStyle: computedStyle,
    confirm: message => { confirmations.push(message); return ui.confirm; },
    fetch: async (url, options) => {
      const call = { method: options.method, url, body: options.body ? JSON.parse(options.body) : undefined };
      calls.push(call);
      const fixtureKey = call.method + ' ' + url;
      if (Object.hasOwn(opts.responses || {}, fixtureKey)) {
        const fixture = opts.responses[fixtureKey];
        const response = typeof fixture === 'function' ? await fixture(call) : fixture;
        const status = response.status ?? 200;
        return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(response.body) };
      }
      let body;
      if (options.method === 'PUT' && /^\/api\/envs\/[^/]+\/secrets$/.test(url)) body = { deployed: call.body.secrets.length };
      else if (options.method === 'POST' && /^\/api\/envs\/[^/]+\/secrets\/reuse-check$/.test(url)) {
        if (opts.reuseFail) return { ok: false, status: 500, text: async () => JSON.stringify({ error: 'preflight unavailable' }) };
        body = { enabled: true, matches: (call.body.exclude || []).includes('saved-secret') ? [] : reuse };
      }
      else if (options.method === 'PUT' && url === '/api/apps/app-a/settings') body = { ok: true };
      else if (options.method === 'PUT' && url === '/api/orgs/org-a/settings') body = { ok: true };
      else if (options.method === 'DELETE' && url === '/api/secrets/saved-secret') body = {};
      // These routes return success so a forbidden staged-row request fails an assertion, not the harness.
      else if (/^\/api\/secrets\/new-[^/]+(?:\/history)?$/.test(url)) body = url.endsWith('/history') ? [] : {};
      else if (options.method === 'POST' && url === '/api/auth/ldap') body = { mfa_required: true, mfa_token: 'mfa-1' };
      else if (options.method === 'POST' && url === '/api/auth/mfa') body = { token: 'session-token' };
      else if (options.method === 'POST' && url === '/api/orgs/org-a/ssh/cas') body = { id: 'ca-ssh-1', name: 'ssh-ca', public_key: 'ssh-ed25519 AAAAC3Nza', fingerprint: 'SHA256:fixture', sshd: 'TrustedUserCAKeys /etc/ssh/openwarp/ca.pub' };
      else if (options.method === 'PUT' && url === '/api/ssh/cas/ca-ssh-1/grants') body = { ca_id: 'ca-ssh-1', roles: call.body.grants.map(g => g.role) };
      else if (options.method === 'POST' && url === '/api/ssh/certs/ssh-cert-1/revoke') body = { revoked: 'ssh-cert-1' };
      else if (options.method === 'POST' && url === '/api/ssh/cas/ca-ssh-1/hosts') body = { id: 'host-2', hostname: call.body.hostname, fingerprint: 'SHA256:newhost' };
      else if (options.method === 'DELETE' && url === '/api/ssh/cas/ca-ssh-1/hosts/host-1') body = { deleted: 'host-1' };
      else if (options.method === 'GET' && Object.hasOwn(responses, url)) body = responses[url];
      else { unexpected.push(call); throw new Error('Unexpected fixture request: ' + options.method + ' ' + url); }
      return { ok: true, status: 200, text: async () => JSON.stringify(body) };
    },
  });
  const ui = {
    document, calls, confirmations, confirm: false,
    el(id) { const el = document.getElementById(id); assert.ok(el, 'missing rendered element #' + id); return el; },
    run(code) { return vm.runInContext(code, context, { timeout: 1000 }); },
    async settle() {
      for (let n = 0; n < 30; n++) await Promise.resolve();
      assert.deepEqual(unexpected, [], 'all requests must have fixture responses');
    },
    async invoke(code) { await this.run(code); await this.settle(); },
    async click(element) {
      assert.ok(element, 'the requested control must exist');
      assert.ok(!element.disabled && !hidden(element), 'the requested control must be interactive');
      element.focus();
      context.__target = element;
      context.__event = { type: 'click', target: element, preventDefault() {} };
      if (element.getAttribute('onclick')) await this.run(`(async function(event){${element.getAttribute('onclick')}}).call(__target,__event)`);
      else if (element.onclick) await element.onclick(context.__event);
      element.dispatchEvent(context.__event);
      await this.settle();
    },
    button(root, name) {
      return root.querySelectorAll('button').find(b => !b.disabled && (b.getAttribute('aria-label') || b.getAttribute('title') || b.textContent).trim().match(name));
    },
    rows() { return this.el('stable').querySelectorAll('tbody tr'); },
    row(key) { return this.rows().find(row => row.textContent.includes(key)); },
    async add(values = draft) {
      await this.click(this.button(this.el('view'), /New secret/));
      this.el('ns-key').value = values.key;
      this.el('ns-val').value = values.value;
      this.el('ns-path').value = values.path;
      this.el('ns-type').value = values.type;
      await this.click(this.button(this.el('modal'), /^Stage secret$/));
    },
    async deploy() { await this.click(this.button(this.el('deploybar'), /^Deploy changes$/)); },
    writes() { return calls.filter(c => c.method !== 'GET' && !/^\/api\/envs\/[^/]+\/secrets\/reuse-check$/.test(c.url)); },
    key(key, shiftKey = false) {
      const event = { type: 'keydown', key, shiftKey, metaKey: false, ctrlKey: false };
      document.activeElement.dispatchEvent(event);
      return event;
    },
    flushTimers() { const pending = timers.splice(0); for (const fn of pending) fn(); },
  };
  context.window = context;
  vm.runInContext(script, context, { filename: 'console-inline.js', timeout: 1000 });
  await ui.invoke('enterApp()');
  await ui.invoke("openApp('app-a')");
  calls.length = 0;
  return ui;
}

function assertDraftDeploy(ui) {
  const writes = ui.writes();
  assert.equal(writes.length, 1, 'one explicit deploy must make exactly one write');
  assert.equal(writes[0].method, 'PUT');
  assert.equal(writes[0].url, '/api/envs/env-a/secrets', 'drafts must deploy to their original environment');
  assert.deepEqual(writes[0].body, { secrets: [draft] }, 'the draft must survive the transition unchanged');
}

for (const dismissal of ['Cancel', 'Escape', 'backdrop']) {
  test(`dismissing New secret with ${dismissal} leaves no deployable draft`, async () => {
    const ui = await consoleUI();
    await ui.click(ui.button(ui.el('view'), /New secret/));
    if (dismissal === 'Cancel') await ui.click(ui.button(ui.el('modal'), /^Cancel$/));
    else if (dismissal === 'Escape') ui.key('Escape');
    else ui.el('modalwrap').dispatchEvent({ type: 'click', target: ui.el('modalwrap') });
    await ui.invoke('drawSecrets(); updateDeployBar()');
    assert.equal(ui.rows().length, 1, 'cancelling must not leave a blank new-secret row');
    assert.ok(hidden(ui.el('deploybar')), 'cancelling must not enable deployment');
    assert.deepEqual(ui.writes(), []);
  });
}

test('the integration picker lists the cloud secret stores and the signed webhook hint', () => {
  const kinds = source.match(/const KINDS=\[([^\]]*)\]/)?.[1] ?? '';
  for (const kind of ['digitalocean', 'scaleway_secret_manager', 'azure_app_configuration', 'vultr', 'hetzner', 'linode', 'digitalocean_ssh', 'ssh', 'webhook']) {
    assert.ok(kinds.includes(`'${kind}'`), `${kind} must be selectable`);
  }
  assert.match(source, /signing_secret/, 'the webhook hint must mention the signing secret');
});

test('a valid new secret stages locally and deploys only on explicit Deploy', async () => {
  const ui = await consoleUI();
  await ui.add({ ...draft, key: 'new_config' });
  assert.ok(ui.row('NEW_CONFIG'), 'submitted keys retain uppercase normalization');
  assert.equal(ui.rows().length, 2);
  assert.deepEqual(ui.writes(), [], 'staging must not persist a secret');
  assert.ok(!hidden(ui.el('deploybar')));
  await ui.deploy();
  assertDraftDeploy(ui);
});

test('editing a staged new secret opens its draft value and updates the pending deploy', async () => {
  const ui = await consoleUI();
  await ui.add();
  await ui.click(ui.button(ui.row(draft.key), /^Edit$/));
  assert.ok(!hidden(ui.el('modalwrap')), 'a new staged row must be editable');
  const value = ui.el('modal').querySelector('textarea');
  assert.ok(value, 'the draft editor must include a value field');
  assert.equal(value.value, draft.value, 'reopening a draft must show the staged value');
  value.value = 'fixture-edited';
  await ui.click(ui.button(ui.el('modal'), /^Stage (change|secret)$/));
  assert.deepEqual(ui.writes(), [], 'editing a draft must remain local');
  assert.match(ui.row(draft.key).textContent, /new/i, 'editing must retain its new-secret status');
  await ui.deploy();
  assert.deepEqual(ui.writes().map(c => [c.method, c.url, c.body]), [
    ['PUT', '/api/envs/env-a/secrets', { secrets: [{ ...draft, value: 'fixture-edited' }] }],
  ]);
});

test('removing a staged new secret removes only the local draft', async () => {
  const ui = await consoleUI();
  await ui.add();
  ui.confirm = true;
  await ui.click(ui.button(ui.row(draft.key), /^(Delete|Remove)$/));
  assert.deepEqual(ui.writes(), [], 'an unsaved secret must never issue server DELETE');
  assert.equal(ui.row(draft.key), undefined);
  assert.equal(ui.rows().length, 1, 'saved secrets must remain intact');
  assert.ok(hidden(ui.el('deploybar')), 'removing the last draft must deactivate deployment');
});

test('staged new rows cannot request server history or personal overrides', async () => {
  const ui = await consoleUI();
  await ui.add();
  const row = ui.row(draft.key);
  for (const name of [/^History$/, /^Personal override$/]) {
    const control = ui.button(row, name);
    if (control && !hidden(control)) await ui.click(control);
  }
  assert.deepEqual(ui.calls, [], 'unsaved rows have no server history or override identity');
  assert.ok(hidden(ui.el('modalwrap')), 'unavailable server actions must not open misleading dialogs');
});

test('refusing an environment change preserves the draft and its deploy target', async () => {
  const ui = await consoleUI();
  await ui.add();
  await ui.invoke("switchEnv('env-b')");
  assert.ok(ui.row(draft.key), 'refusing discard must leave the original draft visible');
  await ui.deploy();
  assertDraftDeploy(ui);
});

test('explicitly accepting environment discard removes the previous draft', async () => {
  const ui = await consoleUI();
  await ui.add();
  ui.confirm = true;
  await ui.invoke("switchEnv('env-b')");
  assert.ok(ui.confirmations.length > 0, 'destructive scope changes require an explicit decision');
  assert.equal(ui.row(draft.key), undefined);
  assert.ok(hidden(ui.el('deploybar')));
  assert.deepEqual(ui.writes(), []);
});

for (const boundary of ['navigation', 'app', 'organization']) {
  test(`${boundary} round trips never silently lose or retarget a draft`, async () => {
    const ui = await consoleUI();
    await ui.add();
    // A false confirmation permits cancellation or scoped preservation, never implicit discard.
    if (boundary === 'navigation') {
      await ui.click(ui.document.querySelector('[data-nav="settings"]'));
      await ui.click(ui.document.querySelector('[data-nav="apps"]'));
    } else if (boundary === 'app') {
      await ui.invoke("openApp('app-b')");
    } else {
      ui.el('orgs').value = 'org-b';
      await ui.invoke('switchOrg()');
      ui.el('orgs').value = 'org-a';
      await ui.invoke('switchOrg()');
    }
    await ui.invoke("openApp('app-a')");
    assert.ok(ui.row(draft.key), 'the original environment must still expose its staged draft');
    await ui.deploy();
    assertDraftDeploy(ui);
  });
}

test('a different app cannot expose or deploy another environment draft', async () => {
  const ui = await consoleUI();
  await ui.add();
  await ui.invoke("openApp('app-b')");
  if (ui.el('pagetitle').textContent === 'Second app') {
    assert.equal(ui.row(draft.key), undefined, 'draft rows must be scoped to their environment');
    assert.ok(hidden(ui.el('deploybar')), 'another app cannot deploy this app draft');
    const blockedDeploy = ui.button(ui.el('deploybar'), /^Deploy changes$/);
    if (blockedDeploy && !hidden(blockedDeploy)) await ui.click(blockedDeploy);
    assert.deepEqual(ui.writes(), []);
  } else {
    assert.ok(ui.row(draft.key), 'a cancelled transition retains the original draft');
  }
});

test('leaving the secrets view deactivates the deploy bar', async () => {
  const ui = await consoleUI();
  await ui.add();
  await ui.click(ui.document.querySelector('[data-nav="settings"]'));
  if (ui.el('pagetitle').textContent === 'Settings') {
    assert.ok(hidden(ui.el('deploybar')), 'non-secret views must not retain an actionable deploy bar');
  } else {
    assert.ok(ui.row(draft.key), 'a cancelled navigation must preserve the draft');
  }
});

test('filter no-match is distinct from an empty environment and clearing restores rows', async () => {
  const ui = await consoleUI();
  const empty = await consoleUI([]);
  const emptyText = empty.el('stable').textContent.trim();
  assert.match(emptyText, /no secrets/i);
  ui.el('sfilter').value = 'not-present';
  await ui.invoke('drawSecrets()');
  const noMatch = ui.el('stable').textContent.trim();
  assert.notEqual(noMatch, emptyText, 'filtering existing secrets must not claim the environment has none');
  assert.match(noMatch, /no .*match|no results/i);
  ui.el('sfilter').value = 'SERVICE';
  await ui.invoke('drawSecrets()');
  assert.ok(ui.row(saved.key), 'path matching remains case-insensitive');
  ui.el('sfilter').value = '';
  await ui.invoke('drawSecrets()');
  assert.equal(ui.rows().length, 1);
});

test('the same key/path filter applies to staged new secrets', async () => {
  const ui = await consoleUI([]);
  await ui.add();
  ui.el('sfilter').value = 'not-present';
  await ui.invoke('drawSecrets()');
  assert.equal(ui.rows().length, 0, 'nonmatching staged rows must not bypass the filter');
  assert.match(ui.el('stable').textContent, /no .*match|no results/i);
  ui.el('sfilter').value = 'DRAFT';
  await ui.invoke('drawSecrets()');
  assert.ok(ui.row(draft.key));
  ui.el('sfilter').value = '';
  await ui.invoke('drawSecrets()');
  await ui.deploy();
  assertDraftDeploy(ui);
});

test('New secret is a named modal dialog with programmatically labeled fields', async () => {
  const ui = await consoleUI();
  await ui.click(ui.button(ui.el('view'), /New secret/));
  const dialog = [ui.el('modalwrap'), ui.el('modal')].find(el => el.tagName === 'DIALOG' || el.getAttribute('role') === 'dialog');
  assert.ok(dialog, 'modal markup must expose dialog semantics');
  assert.equal(dialog.getAttribute('aria-modal'), 'true');
  const label = dialog.getAttribute('aria-label') || (dialog.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean).map(id => ui.el(id).textContent).join(' ');
  assert.match(label, /new secret/i, 'the dialog must have an accessible name');
  for (const field of ui.el('modal').querySelectorAll('input,textarea,select')) {
    const hasLabel = field.getAttribute('aria-label') || field.getAttribute('aria-labelledby')?.split(/\s+/).every(id => ui.document.getElementById(id)?.textContent.trim()) ||
      field.closest('label') || ui.el('modal').querySelectorAll('label').some(label => label.getAttribute('for') === field.id && label.textContent.trim());
    assert.ok(hasLabel, `dialog field ${field.id} must have a programmatic label`);
  }
});

test('dialogs move focus inside, wrap keyboard focus, and restore it on Escape', async () => {
  const ui = await consoleUI();
  const opener = ui.button(ui.el('view'), /New secret/);
  await ui.click(opener);
  ui.flushTimers();
  assert.equal(ui.document.activeElement, ui.el('ns-key'), 'opening a dialog must focus its first field');
  const controls = ui.el('modal').querySelectorAll('input,textarea,select,button').filter(el => !el.disabled && !hidden(el));
  const first = controls[0], last = controls.at(-1);
  last.focus();
  ui.key('Tab');
  assert.equal(ui.document.activeElement, first, 'Tab at the end of a modal must wrap inside');
  first.focus();
  ui.key('Tab', true);
  assert.equal(ui.document.activeElement, last, 'Shift+Tab at the start must wrap inside');
  ui.key('Escape');
  ui.flushTimers();
  assert.ok(hidden(ui.el('modalwrap')));
  assert.equal(ui.document.activeElement, opener, 'closing a dialog must restore the invoking control');
});

test('the inactive deploy bar is hidden rather than merely translated offscreen', async () => {
  const ui = await consoleUI();
  assert.ok(hidden(ui.el('deploybar')), 'an inactive deploy bar must be absent from visibility and keyboard navigation');
  await ui.add();
  assert.ok(!hidden(ui.el('deploybar')), 'staging must expose the deploy controls');
  await ui.click(ui.button(ui.el('deploybar'), /^Discard$/));
  assert.ok(hidden(ui.el('deploybar')), 'discard must hide the bar again');
  assert.equal(ui.row(draft.key), undefined);
  assert.deepEqual(ui.writes(), []);
});

test('saved-secret history and deletion retain their existing server routes', async () => {
  const ui = await consoleUI();
  assert.equal(ui.row(saved.key).querySelector('.val').textContent, '••••••••••', 'values remain masked by default');
  await ui.click(ui.button(ui.row(saved.key), /^History$/));
  assert.deepEqual(ui.calls.map(c => [c.method, c.url]), [['GET', '/api/secrets/saved-secret/history']]);
  await ui.invoke('closeModal()');
  ui.confirm = true;
  await ui.click(ui.button(ui.row(saved.key), /^Delete$/));
  assert.deepEqual(ui.writes().map(c => [c.method, c.url]), [['DELETE', '/api/secrets/saved-secret']]);
});

test('the reset view asks for the kit and an explicit key replacement', async () => {
  const ui = await consoleUI();
  await ui.invoke("showReset('reset-token-1')");
  assert.equal(ui.el('auth').style.display, 'grid', 'the reset view belongs on the auth screen');
  assert.equal(ui.el('authform').dataset.reset, 'reset-token-1', 'the token must be carried into the form');
  for (const id of ['rp-pw', 'rp-kit', 'rp-discard']) assert.ok(ui.document.getElementById(id), `missing #${id}`);
  for (const id of ['rp-pw', 'rp-kit']) {
    const label = ui.el('authform').querySelectorAll('label').find(l => l.getAttribute('for') === id);
    assert.ok(label && label.textContent.trim(), `#${id} needs a programmatic label`);
  }
  assert.match(ui.el('authform').textContent, /lose end-to-end access/i, 'replacing the key must state its cost');
});

test('directory sign-in carries the workspace and completes the second factor', async () => {
  const ui = await consoleUI();
  await ui.invoke('ldapPrompt()');
  for (const id of ['ld-org', 'ld-user', 'ld-pw']) assert.ok(ui.document.getElementById(id), `missing ${id}`);
  ui.el('ld-org').value = 'org-a';
  ui.el('ld-user').value = 'bob';
  ui.el('ld-pw').value = 'user-secret';
  await ui.invoke('ldapSignIn()');
  assert.deepEqual(ui.calls.map(c => [c.method, c.url]), [['POST', '/api/auth/ldap']]);
  assert.deepEqual(ui.calls[0].body, { org_id: 'org-a', username: 'bob', password: 'user-secret' },
    'the directory request must carry the workspace id, username and password only');
  assert.ok(ui.document.getElementById('ld-mfa'), 'an MFA challenge must render the code field');
  ui.el('ld-mfa').value = '123456';
  ui.calls.length = 0;
  await ui.invoke('ldapMfa()');
  assert.deepEqual(ui.calls[0].body, { mfa_token: 'mfa-1', code: '123456' });
});

test('the LDAP settings card is absent when the server does not advertise the provider', async () => {
  const ui = await consoleUI();
  ui.run("ORG='org-a'");
  await ui.invoke('renderSettings()');
  assert.equal(ui.document.getElementById('ld-url'), null,
    'a build without the ldap feature must not render directory settings');
  assert.ok(ui.document.getElementById('set-oidc-iss'), 'the rest of the settings view still renders');
});

const reuseMatch = { key: 'NEW_CONFIG', path: '/draft', items: [{ secret_id: 'saved-secret', key: 'DATABASE_URL', path: '/service', app_id: 'app-a', app_name: 'First app', env_id: 'env-a', env_name: 'Development' }] };

test('a reused value warns before staging, can be saved anyway, and is not a write', async () => {
  const ui = await consoleUI([saved], [reuseMatch]);
  await ui.add({ ...draft, type: 'secret' });
  assert.match(ui.el('modal').textContent, /already in use/i);
  assert.match(ui.el('modal').textContent, /DATABASE_URL/);
  assert.match(ui.el('modal').textContent, /Development/);
  assert.equal(ui.rows().length, 1, 'nothing may be staged until the warning is acknowledged');
  assert.ok(hidden(ui.el('deploybar')), 'the warning must not enable deployment');
  assert.deepEqual(ui.writes(), [], 'the preflight is not a write');
  await ui.click(ui.button(ui.el('modal'), /^Use anyway$/));
  assert.ok(ui.row('NEW_CONFIG'), 'Use anyway must stage the draft');
  assert.ok(!hidden(ui.el('deploybar')), 'the acknowledged draft becomes deployable');
  assert.deepEqual(ui.writes(), [], 'staging stays local');
});

test('Back from a reuse warning restores the new-secret form', async () => {
  const ui = await consoleUI([saved], [reuseMatch]);
  await ui.add({ ...draft, type: 'secret' });
  await ui.click(ui.button(ui.el('modal'), /^Back$/));
  assert.equal(ui.el('ns-key').value, draft.key);
  assert.equal(ui.el('ns-val').value, draft.value);
  assert.equal(ui.el('ns-path').value, draft.path);
  assert.equal(ui.el('ns-type').value, 'secret');
  assert.ok(hidden(ui.el('deploybar')), 'backing out must not stage anything');
});

test('Go to leaves the warning and filters the matching environment', async () => {
  const ui = await consoleUI([saved], [reuseMatch]);
  await ui.add({ ...draft, type: 'secret' });
  await ui.click(ui.button(ui.el('modal'), /^Go to$/));
  assert.ok(!ui.el('modalwrap').classList.contains('show'), 'navigation must close the warning');
  assert.equal(ui.el('sfilter').value, 'DATABASE_URL');
  assert.ok(ui.row('DATABASE_URL'), 'the matching row must be visible');
  assert.ok(hidden(ui.el('deploybar')), 'navigation must not stage the pending secret');
});

test('workspace and app settings expose the reuse switch', async () => {
  const ui = await consoleUI();
  ui.run("ORG='org-a'");
  await ui.invoke('renderSettings()');
  assert.ok(ui.el('set-reuse').hasAttribute('checked'), 'the workspace switch defaults on');
  ui.el('set-reuse').checked = false;
  await ui.invoke('saveSettings()');
  const orgPut = ui.calls.find(c => c.method === 'PUT' && c.url === '/api/orgs/org-a/settings');
  assert.ok(orgPut, 'saving settings must reach the workspace endpoint');
  assert.equal(orgPut.body.reuse_check, false, 'the workspace switch must be saved');
  ui.run("APP={id:'app-a',name:'First app'};ENVS=[{id:'env-a',name:'Development'}];ENV=ENVS[0];SECRETS=[];DRAFTS={}");
  await ui.invoke('appSettings()');
  assert.ok(ui.el('app-reuse').hasAttribute('checked'), 'the app switch defaults on');
  ui.el('app-reuse').checked = false;
  await ui.invoke('saveAppSettings()');
  const appPut = ui.calls.find(c => c.method === 'PUT' && c.url === '/api/apps/app-a/settings');
  assert.ok(appPut, 'saving app settings must reach the app endpoint');
  assert.equal(appPut.body.reuse_check, false, 'the app switch must be saved');
});

test('SSH CA settings create a CA, edit grants and revoke a certificate', async () => {
  const ui = await consoleUI();
  ui.run("ORG='org-a'");
  await ui.invoke('renderSettings()');
  assert.ok(ui.el('ssh-ca-list').textContent.includes('No SSH CA yet'), 'an empty workspace explains what is missing');
  ui.el('ssh-ca-name').value = 'ssh-ca';
  await ui.click(ui.button(ui.el('view'), /^Create SSH CA$/));
  const create = ui.calls.find(c => c.method === 'POST' && c.url === '/api/orgs/org-a/ssh/cas');
  assert.ok(create, 'creating a CA must reach the workspace');
  assert.equal(create.body.name, 'ssh-ca');
  assert.ok(ui.el('ca-out').textContent.includes('SHA256:fixture'), 'the new CA reports its fingerprint');
  assert.ok(ui.el('ssh-ca-detail').textContent.includes('TrustedUserCAKeys'), 'the new CA opens straight to the sshd block');
  await ui.invoke("openSshCA('ca-ssh-1')");
  assert.ok(ui.el('ssh-grants').value.includes('developer: web-*'), 'existing grants load into the editor');
  ui.el('ssh-grants').value = 'developer: web-*, db-1 (30m)\nadmin: *';
  await ui.invoke("saveSshGrants('ca-ssh-1')");
  const put = ui.calls.find(c => c.method === 'PUT' && c.url === '/api/ssh/cas/ca-ssh-1/grants');
  assert.ok(put, 'saving grants must reach the CA');
  assert.deepEqual(put.body.grants[0].principals, ['web-*', 'db-1'], 'comma-separated patterns are split');
  assert.equal(put.body.grants[0].max_ttl, 1800, 'a trailing (30m) sets the maximum lifetime');
  assert.deepEqual(put.body.grants[1].principals, ['*'], 'the owner pattern survives the editor');
  ui.confirm = false;
  await ui.invoke("revokeSshCert('ssh-cert-1','ca-ssh-1')");
  assert.ok(!ui.calls.some(c => c.url === '/api/ssh/certs/ssh-cert-1/revoke'), 'a dismissed confirm must not revoke');
  ui.confirm = true;
  await ui.invoke("revokeSshCert('ssh-cert-1','ca-ssh-1')");
  assert.ok(ui.calls.some(c => c.method === 'POST' && c.url === '/api/ssh/certs/ssh-cert-1/revoke'), 'confirming revokes');
  assert.ok(ui.el('ssh-hosts').textContent.includes('db-1.internal'), 'the registered hosts are listed');
  ui.el('ssh-host-name').value = 'cache-1.internal';
  ui.el('ssh-host-key').value = 'ssh-ed25519 AAAAC3Nza host';
  await ui.invoke("addSshHost('ca-ssh-1')");
  const hostPost = ui.calls.find(c => c.method === 'POST' && c.url === '/api/ssh/cas/ca-ssh-1/hosts');
  assert.ok(hostPost, 'registering a host must reach the CA');
  assert.equal(hostPost.body.hostname, 'cache-1.internal');
  assert.ok(hostPost.body.public_key.includes('ssh-ed25519'), 'the host key is sent for pinning');
  assert.ok(!ui.el('ssh-host-name').value, 'the form clears after registering');
  ui.confirm = true;
  await ui.invoke("deleteSshHost('host-1','ca-ssh-1')");
  assert.ok(ui.calls.some(c => c.method === 'DELETE' && c.url === '/api/ssh/cas/ca-ssh-1/hosts/host-1'), 'removing a host reaches the CA');
});

test('re-editing a draft back to its stored value does not match itself', async () => {
  const ui = await consoleUI([saved], [reuseMatch]);
  await ui.click(ui.button(ui.row('DATABASE_URL'), /^Edit$/));
  ui.el('ed-val').value = 'fixture-changed';
  await ui.click(ui.button(ui.el('modal'), /^Stage (change|secret)$/));
  assert.ok(!hidden(ui.el('deploybar')), 'the changed value becomes a draft');
  await ui.click(ui.button(ui.row('DATABASE_URL'), /^Edit$/));
  assert.equal(ui.el('ed-val').value, 'fixture-changed', 'the draft value reopens');
  ui.el('ed-val').value = 'fixture-original';
  await ui.click(ui.button(ui.el('modal'), /^Stage (change|secret)$/));
  const preflights = ui.calls.filter(c => /reuse-check$/.test(c.url));
  assert.ok(preflights.length >= 1, 'the edit must run the preflight');
  assert.deepEqual(preflights[preflights.length - 1].body.exclude, ['saved-secret'],
    'editing a stored secret must exclude its own id');
  assert.ok(!ui.el('modalwrap').classList.contains('show'),
    'returning to the stored value must not warn about itself');
});

test('a failed reuse preflight leaves staging available', async () => {
  const ui = await consoleUI([saved], [], { reuseFail: true });
  await ui.add({ ...draft, type: 'secret' });
  assert.ok(ui.row('NEW_CONFIG'), 'the draft must still stage');
  assert.ok(!hidden(ui.el('deploybar')), 'the draft remains deployable');
  assert.ok(!ui.el('modalwrap').classList.contains('show'), 'a failed check must not open a dialog');
});

const aiPolicy = {
  enabled: true, allow_metadata: true, allow_actions: true, allow_local_search: false,
  monitoring_enabled: false, can_admin: true, has_api_key: true,
  endpoint: 'https://ai.test.invalid/v1/chat/completions', model: 'fixture-model',
  allowed_endpoints: ['https://ai.test.invalid/v1/chat/completions'],
  request_limit: 100, token_limit: 100000, max_output_tokens: 1024,
};
const folderOps = [{ kind: 'create_folder', env_id: 'env-a', path: '/reviewed-folder' }];
const aiPlan = { id: 'plan-fixture', status: 'pending', operations: folderOps, expires_at: 2000000000 };
function aiFixtures(policy = {}, extra = {}) {
  return {
    'GET /api/orgs/org-a/ai/settings': { body: { ...aiPolicy, ...policy } },
    'GET /api/orgs/org-a/ai/context': { body: { envs: [{ id: 'env-a', app_id: 'app-a', app_name: 'First app', name: 'Development', mode: 'sse' }], integrations: [] } },
    'GET /api/orgs/org-a/ai/drafts': { body: { drafts: [] } },
    ...extra,
  };
}
async function assistantUI(policy = {}, extra = {}) {
  const ui = await consoleUI([saved], [], { responses: aiFixtures(policy, extra) });
  await ui.click(ui.document.querySelector('[data-nav="assistant"]'));
  return ui;
}
async function prepareFolder(ui) {
  await ui.click(ui.button(ui.el('view'), /^Prepare folder$/));
  ui.el('ai-op-env').value = 'env-a';
  ui.el('ai-op-path').value = '/reviewed-folder';
  await ui.click(ui.button(ui.el('modal'), /^Preview changes$/));
}
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

test('assistant defaults off without context fetch, questions or inference', async () => {
  const ui = await assistantUI({ enabled: false, allow_metadata: false, allow_actions: false });
  assert.match(ui.el('view').textContent, /assistant is off/i);
  assert.equal(ui.document.getElementById('ai-question'), null);
  assert.deepEqual(ui.calls.map(c => [c.method, c.url]), [['GET', '/api/orgs/org-a/ai/settings']]);
  await ui.click(ui.button(ui.el('view'), /^Assistant settings$/));
  for (const flag of ['enabled', 'allow_metadata', 'allow_actions']) assert.equal(ui.el('ai-set-' + flag).checked, false);
  assert.deepEqual(ui.writes(), [], 'opening disabled assistant and policy must never infer or persist');
});

test('metadata search stays a GET without secret values or model requests', async () => {
  const ui = await assistantUI({}, {
    'GET /api/orgs/org-a/ai/search?q=DATABASE&env_id=env-a': { body: { results: [{ id: saved.id, key: saved.key, path: saved.path, env_id: 'env-a', app_id: 'app-a' }] } },
  });
  ui.calls.length = 0;
  ui.el('ai-search').value = 'DATABASE';
  await ui.click(ui.el('ai-search-btn'));
  assert.deepEqual(ui.calls, [{ method: 'GET', url: '/api/orgs/org-a/ai/search?q=DATABASE&env_id=env-a', body: undefined }]);
  assert.match(ui.el('ai-search-results').textContent, /DATABASE_URL/);
  assert.ok(!ui.el('view').textContent.includes(saved.value));
  assert.ok(!JSON.stringify(ui.calls).includes(saved.value), 'stored secret values must not be assembled into search requests');
});

test('assistant answers and source labels render hostile model text without HTML elements', async () => {
  const hostile = '<img src=x onerror="alert(1)"><script>bad()</script>';
  const ui = await assistantUI({}, {
    'POST /api/orgs/org-a/ai/chat': { body: { answer: hostile, citations: [{ id: 'source-fixture', key: hostile, path: hostile, app_name: hostile, env_name: hostile, app_id: 'app-a', env_id: 'env-a' }], suggested_operations: [] } },
  });
  ui.el('ai-question').value = 'Where is the database key?';
  await ui.click(ui.el('ai-ask'));
  assert.ok(ui.el('ai-answer').textContent.includes(hostile), 'escaping must preserve the literal answer and citation text');
  assert.equal(ui.el('ai-answer').querySelectorAll('img,script').length, 0, 'model and citation content must never create markup');
  assert.ok(ui.el('ai-answer').querySelectorAll('button').every(b => /^aiOpenRef\(\d+\)$/.test(b.getAttribute('onclick'))), 'source actions use local references, not model-authored handlers');
});

test('import content uses its dedicated field and never becomes the model question', async () => {
  const ui = await assistantUI({}, {
    'POST /api/orgs/org-a/ai/chat': { body: { answer: 'Use a service folder.', citations: [], suggested_operations: [] } },
  });
  ui.el('ai-task').value = 'import';
  await ui.invoke('aiTaskChanged()');
  assert.ok(!hidden(ui.el('ai-import-wrap')));
  assert.match(ui.el('ai-disclosure').textContent, /do not type passwords, keys, or connection strings/i);
  const importText = 'DATABASE_URL=fake-import-private-value\nAPI_KEY=fake-import-key';
  ui.el('ai-question').value = 'Suggest folder names for this import';
  ui.el('ai-import').value = importText;
  await ui.click(ui.el('ai-ask'));
  const request = ui.calls.find(c => c.method === 'POST' && c.url.endsWith('/ai/chat'));
  assert.deepEqual(request.body, { message: 'Suggest folder names for this import', task: 'import', env_id: 'env-a', import_text: importText });
  assert.ok(!request.body.message.includes('fake-import-'));
  assert.ok(!request.body.message.includes(saved.value));
  assert.equal(ui.el('ai-import').value, '', 'discard raw import input after a successful response');
});

test('folder setup previews exact operations and executes only after Confirm with a minimal body', async () => {
  const ui = await assistantUI({}, {
    'POST /api/orgs/org-a/ai/plans': { body: aiPlan },
    'POST /api/orgs/org-a/ai/plans/plan-fixture/execute': { body: { results: [{ kind: 'create_folder', status: 'created' }] } },
  });
  ui.calls.length = 0;
  await prepareFolder(ui);
  assert.deepEqual(ui.writes(), [{ method: 'POST', url: '/api/orgs/org-a/ai/plans', body: { operations: folderOps } }]);
  assert.match(ui.el('ai-plan').textContent, /reviewed-folder/);
  assert.equal(ui.el('ai-plan').querySelectorAll('input,textarea,select').length, 0, 'preview operations are not editable');
  await ui.click(ui.el('ai-confirm'));
  const execute = ui.calls.filter(c => c.url.endsWith('/execute'));
  assert.deepEqual(execute, [{ method: 'POST', url: '/api/orgs/org-a/ai/plans/plan-fixture/execute', body: { confirm: true } }]);
  await ui.invoke('aiExecutePlan()');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/execute')).length, 1, 'repeated activation cannot reuse the consumed preview');
});

test('workspace switches discard previews and stale chat responses cannot populate the new workspace', async () => {
  const pending = deferred();
  const ui = await assistantUI({}, {
    'POST /api/orgs/org-a/ai/plans': { body: aiPlan },
    'POST /api/orgs/org-a/ai/chat': () => pending.promise,
    'GET /api/orgs/org-b/ai/settings': { body: { ...aiPolicy, enabled: false } },
  });
  await prepareFolder(ui);
  ui.el('ai-question').value = 'Ask the old workspace';
  const asking = ui.run('aiAsk()');
  await ui.settle();
  ui.el('orgs').value = 'org-b';
  await ui.invoke('switchOrg()');
  await ui.click(ui.document.querySelector('[data-nav="assistant"]'));
  const newWorkspace = ui.el('view').textContent;
  pending.resolve({ body: { answer: 'STALE_ORG_A_PRIVATE_RESPONSE', citations: [], suggested_operations: folderOps } });
  await asking;
  await ui.settle();
  assert.equal(ui.el('view').textContent, newWorkspace);
  assert.ok(!ui.el('view').textContent.includes('STALE_ORG_A_PRIVATE_RESPONSE'));
  assert.equal(ui.document.getElementById('ai-confirm'), null);
  await ui.invoke('aiExecutePlan()');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/execute')).length, 0, 'old workspace preview must no longer execute');
});

test('reset discards a preview and a pending plan response cannot restore it', async () => {
  const pending = deferred();
  let requests = 0;
  const ui = await assistantUI({}, {
    'POST /api/orgs/org-a/ai/plans': () => ++requests === 1 ? { body: aiPlan } : pending.promise,
  });
  await prepareFolder(ui);
  await ui.invoke('aiReset(); aiExecutePlan()');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/execute')).length, 0);
  await ui.click(ui.document.querySelector('[data-nav="assistant"]'));
  await ui.click(ui.button(ui.el('view'), /^Prepare folder$/));
  ui.el('ai-op-path').value = '/reviewed-folder';
  const planning = ui.run("aiPreviewSetup('create_folder')");
  await ui.settle();
  await ui.invoke('aiReset(); closeModal()');
  pending.resolve({ body: { ...aiPlan, id: 'stale-plan', operations: [{ ...folderOps[0], path: '/STALE_PLAN_RESPONSE' }] } });
  await planning;
  await ui.settle();
  assert.ok(!ui.el('view').textContent.includes('STALE_PLAN_RESPONSE'));
  assert.equal(ui.document.getElementById('ai-confirm'), null);
  await ui.invoke('aiExecutePlan()');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/execute')).length, 0);
});

test('settings preserve a saved provider key when blank and clear it only explicitly', async () => {
  const ui = await assistantUI({}, { 'PUT /api/orgs/org-a/ai/settings': { body: { ok: true } } });
  for (const clear of [false, true]) {
    await ui.click(ui.button(ui.el('view'), /^Assistant settings$/));
    assert.equal(ui.el('ai-set-key').value, '', 'saved key must never populate the password field');
    ui.el('ai-set-clear').checked = clear;
    await ui.click(ui.el('ai-settings-save'));
    const request = ui.calls.filter(c => c.method === 'PUT' && c.url.endsWith('/ai/settings')).at(-1);
    assert.equal(Object.hasOwn(request.body, 'api_key'), false, 'blank replacement must be omitted rather than clearing the key');
    assert.equal(request.body.clear_api_key, clear);
  }
  await ui.click(ui.button(ui.el('view'), /^Assistant settings$/));
  ui.el('ai-set-key').value = 'fake-new-provider-key';
  await ui.click(ui.el('ai-settings-save'));
  assert.equal(ui.calls.filter(c => c.method === 'PUT').at(-1).body.api_key, 'fake-new-provider-key');
});

test('security insights display admin authorization failures instead of an empty findings claim', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    'GET /api/orgs/org-a/ai/findings': { status: 403, body: { error: 'Workspace administrator access required.' } },
  } });
  await ui.click(ui.document.querySelector('[data-nav="insights"]'));
  assert.match(ui.el('view').textContent, /Workspace administrator access required/);
  assert.equal(ui.el('view').getAttribute('role'), 'alert');
  assert.doesNotMatch(ui.el('view').textContent, /No findings/);
  assert.deepEqual(ui.calls.map(c => [c.method, c.url]), [['GET', '/api/orgs/org-a/ai/findings']]);
});
