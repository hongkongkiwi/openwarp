'use strict';

// Run with node --test crates/server/tests/product-ui.test.cjs. No server is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
// The merged console expects the i18n runtime to load before its inline script.
const i18nSource = fs.readFileSync(path.join(__dirname, '../src/i18n.js'), 'utf8');
const html = source.match(/r##"([\s\S]*)"##;/)?.[1];
assert.ok(html, 'embedded console HTML is extractable');
const script = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
  .filter(([, attrs]) => !/\bsrc\s*=/.test(attrs)).map(([, , body]) => body).join('\n');
const decode = value => String(value).replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos|#39);/gi,
  (_, code) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[code] ??
    String.fromCodePoint(code[1].toLowerCase() === 'x' ? parseInt(code.slice(2), 16) : Number(code.slice(1)))));

// This is the existing console suite's DOM model, without its layout-only CSS model.
class Element {
  constructor(tagName, document, attrs = {}) {
    this.tagName = tagName.toUpperCase(); this.ownerDocument = document; this.attributes = { ...attrs };
    this.children = []; this.parentElement = null; this.listeners = {}; this.style = {};
    this.dataset = new Proxy({}, {
      get: (_, key) => this.getAttribute('data-' + String(key).replace(/[A-Z]/g, c => '-' + c.toLowerCase())),
      set: (_, key, value) => { this.setAttribute('data-' + String(key).replace(/[A-Z]/g, c => '-' + c.toLowerCase()), value); return true; },
    });
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(n => !names.includes(n)).join(' '); },
      toggle: (name, force) => { const add = force === undefined ? !this.classList.contains(name) : force; this.classList[add ? 'add' : 'remove'](name); return add; },
    };
    for (const decl of (attrs.style || '').split(';')) {
      const at = decl.indexOf(':'); if (at > 0) this.style[decl.slice(0, at).trim()] = decl.slice(at + 1).trim();
    }
  }
  get id() { return this.getAttribute('id') || ''; }
  get className() { return this.getAttribute('class') || ''; }
  set className(value) { this.setAttribute('class', value); }
  get hidden() { return this.hasAttribute('hidden'); }
  set hidden(value) { value ? this.setAttribute('hidden', '') : this.removeAttribute('hidden'); }
  get disabled() { return this.hasAttribute('disabled'); }
  set disabled(value) { value ? this.setAttribute('disabled', '') : this.removeAttribute('disabled'); }
  get checked() { return this._checked ?? this.hasAttribute('checked'); }
  set checked(value) { this._checked = !!value; }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.tagName === 'TEXTAREA') return this.textContent;
    if (this.tagName === 'SELECT') {
      const options = this.querySelectorAll('option'); const option = options.find(o => o.hasAttribute('selected')) || options[0];
      return option ? option.getAttribute('value') ?? option.textContent : '';
    }
    return this.getAttribute('value') || '';
  }
  set value(value) { this._value = String(value); }
  get textContent() { return this.children.map(c => typeof c === 'string' ? c : c.textContent).join(''); }
  set textContent(value) { this.children = [String(value)]; }
  get innerHTML() { return this.children.map(c => typeof c === 'string' ? c : c.outerHTML).join(''); }
  set innerHTML(value) { this.children = []; parse(String(value), this); }
  get outerHTML() { return `<${this.tagName.toLowerCase()}${Object.entries(this.attributes).map(([k, v]) => ` ${k}="${v}"`).join('')}>${this.innerHTML}</${this.tagName.toLowerCase()}>`; }
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
    event.target ||= this; event.preventDefault ||= () => { event.defaultPrevented = true; };
    for (const listener of this.listeners[event.type] || []) listener(event);
    if (this.parentElement && event.bubbles !== false) this.parentElement.dispatchEvent(event);
    return !event.defaultPrevented;
  }
  matches(selector) {
    let excluded = false; selector = selector.replace(/:not\(([^)]+)\)/g, (_, inner) => { excluded ||= this.matches(inner); return ''; });
    if (excluded || (selector.includes(':disabled') && !this.disabled) || (selector.includes(':enabled') && this.disabled)) return false;
    selector = selector.replace(/:(disabled|enabled)/g, '');
    const tag = selector.match(/^[\w-]+/); if (tag && this.tagName !== tag[0].toUpperCase()) return false;
    for (const [, id] of selector.matchAll(/#([\w-]+)/g)) if (this.id !== id) return false;
    for (const [, name] of selector.matchAll(/\.([\w-]+)/g)) if (!this.classList.contains(name)) return false;
    for (const [, name, , value] of selector.matchAll(/\[([\w-]+)(?:\s*=\s*(["']?)(.*?)\2)?\]/g)) {
      if (!this.hasAttribute(name) || (value !== undefined && this.getAttribute(name) !== value)) return false;
    }
    return true;
  }
  querySelectorAll(selector) {
    const matches = element => selector.split(',').some(part => {
      const chain = part.trim().split(/\s+/); if (!element.matches(chain.pop())) return false;
      let parent = element.parentElement;
      while (chain.length) { const next = chain.pop(); while (parent && !parent.matches(next)) parent = parent.parentElement; if (!parent) return false; parent = parent.parentElement; }
      return true;
    });
    const result = []; const walk = root => { for (const child of root.children) if (typeof child !== 'string') { if (matches(child)) result.push(child); walk(child); } };
    walk(this); return result;
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
    const el = new Element(tag, root.ownerDocument, attrs); stack.at(-1).appendChild(el);
    if (!/^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/i.test(tag)) stack.push(el);
  }
}
function visible(el) {
  for (let p = el; p; p = p.parentElement) if (p.hidden || p.style.display === 'none' || p.style.visibility === 'hidden') return false;
  return true;
}
const clone = value => JSON.parse(JSON.stringify(value));
const request = { id: 'request-a', org_id: 'org-a', title: 'Release configuration', author: 'author-a', revision: 7, status: 'pending', approved_by: '', created_at: 1800000000 };
const detail = { ...request, changes: [{ env_id: 'env-a', items: [
  { key: 'API_KEY', path: '/', before: { key: 'API_KEY', value: 'fixture-before', type: 'secret' }, after: { key: 'API_KEY', value: 'fixture-after', type: 'secret' } },
  { key: 'SEALED', path: '/', before: { key: 'SEALED', value: null, type: 'sealed' }, after: { key: 'SEALED', value: null, type: 'sealed' } },
] }] };
const changes = [
  { env_id: 'env-a', secrets: [{ key: 'API_KEY', value: 'fixture-new', path: '/' }], deletes: [] },
  { env_id: 'env-b', secrets: [], deletes: [{ key: 'OBSOLETE', path: '/' }] },
];
const trust = { id: 'trust-a', identity_id: 'identity-a', issuer: 'https://issuer.test.invalid', audience: 'openwarp', subject: 'repo:fixture:prod', env_id: 'env-b', scopes: ['secrets:read'], ttl: 300, bound_claims: { repository: 'fixture/repo' }, revoked: 0 };
const key = { id: 'key-a', name: 'application-key', current_version: 2, version: 2, created_at: 1800000000 };
const functions = ['renderProductTools', 'productRequestModal', 'saveProductRequest', 'productRequestAction', 'productTrustModal', 'saveProductTrust', 'revokeProductTrust', 'productTransitModal', 'runProductTransit'];

async function consoleUI(opts = {}) {
  const document = new Element('document', null); document.ownerDocument = document;
  document.getElementById = id => document.querySelector('#' + id); document.createElement = tag => new Element(tag, document);
  parse(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<style>[\s\S]*?<\/style>/gi, ''), document);
  document.body = document.querySelector('body'); document.activeElement = document.body;
  const calls = [], unexpected = [], clipboard = [], storage = [], history = [], timers = [];
  let current = clone(opts.request || request), review = clone(opts.detail || detail);
  const role = opts.role || 'admin', uid = opts.uid || 'reviewer-a';
  const routes = {
    '/api/auth/providers': {}, '/api/me': { id: uid, email: 'fixture@test.invalid' },
    '/api/orgs': [{ id: 'org-a', name: 'Workspace A', role }, { id: 'org-b', name: 'Workspace B', role }],
  };
  for (const org of ['org-a', 'org-b']) {
    Object.assign(routes, {
      [`/api/orgs/${org}/apps`]: [{ id: org === 'org-a' ? 'app-a' : 'app-b', name: 'Application' }],
      [`/api/orgs/${org}/members`]: [{ id: uid, email: 'fixture@test.invalid', role }],
      [`/api/orgs/${org}/roles`]: [{ name: role, managed: true, permissions: role === 'admin' || role === 'owner' ? ['*'] : [] }],
      [`/api/orgs/${org}/teams`]: [],
      [`/api/orgs/${org}/invites`]: [],
      [`/api/orgs/${org}/identities`]: [{ id: 'identity-a', org_id: org, name: opts.identityName || 'CI identity', role: 'developer' }],
      [`/api/orgs/${org}/emergency`]: { locked: false },
      [`/api/orgs/${org}/identities/identity-a/workload-trust`]: [clone(trust)],
      [`/api/orgs/${org}/transit/keys`]: [clone(key)],
    });
  }
  routes['/api/apps/app-a/envs'] = [{ id: 'env-a', name: 'Development', mode: 'sse' }, { id: 'env-b', name: 'Production', mode: 'sse' }];
  routes['/api/apps/app-b/envs'] = [{ id: 'env-other', name: 'Other environment', mode: 'sse' }];
  const context = vm.createContext({
    document, console, URL, TextDecoder, TextEncoder,
    localStorage: { getItem: () => '', setItem: (...args) => storage.push(args), removeItem() {} },
    sessionStorage: { getItem: () => '', setItem: (...args) => storage.push(args), removeItem() {} },
    navigator: { language: 'en', languages: ['en'], clipboard: { writeText: async text => clipboard.push(text) } },
    location: { origin: 'http://console.invalid', hash: '', pathname: '/', reload() {} },
    history: { replaceState: (...args) => history.push(args), pushState: (...args) => history.push(args) },
    setTimeout: fn => { timers.push(fn); return timers.length; }, clearTimeout() {},
    setInterval: () => 1, clearInterval() {},
    requestAnimationFrame: fn => { timers.push(fn); return timers.length; }, confirm: () => true,
    fetch: async (url, options) => {
      const call = { method: options.method, url, body: options.body ? JSON.parse(options.body) : undefined }; calls.push(call);
      let body, status = 200;
      if (opts.intercept) {
        const response = await opts.intercept(call);
        if (response) return { ok: (response.status || 200) < 400, status: response.status || 200, text: async () => JSON.stringify(response.body) };
      }
      if (call.method === 'GET' && url === '/api/orgs/org-a/change-requests') body = [current];
      else if (call.method === 'GET' && url === '/api/orgs/org-b/change-requests') body = [];
      else if (call.method === 'GET' && url === '/api/change-requests/request-a') body = review;
      else if (call.method === 'POST' && url === '/api/orgs/org-a/change-requests') body = { id: 'request-new', revision: 1, status: 'pending' };
      else if (call.method === 'PUT' && url === '/api/change-requests/request-a') { current = { ...current, title: call.body.title, revision: current.revision + 1, status: 'pending' }; body = current; }
      else if (call.method === 'POST' && /^\/api\/change-requests\/request-a\/(approve|apply|reject)$/.test(url)) {
        current = { ...current, status: { approve: 'approved', apply: 'applied', reject: 'rejected' }[url.split('/').at(-1)] }; body = { ...current, sync_errors: [] };
      }
      else if (call.method === 'POST' && url === '/api/orgs/org-a/identities/identity-a/workload-trust') body = { ...trust, ...call.body };
      else if (call.method === 'DELETE' && url === '/api/orgs/org-a/identities/identity-a/workload-trust/trust-a') body = { revoked: 'trust-a' };
      else if (call.method === 'POST' && url === '/api/orgs/org-a/transit/keys') body = { ...key, id: 'key-new', name: call.body.name };
      else if (call.method === 'POST' && url === '/api/orgs/org-a/transit/keys/key-a/rotate') body = { ...key, current_version: 3, version: 3 };
      else if (call.method === 'POST' && /^\/api\/orgs\/org-a\/transit\/keys\/key-a\/(encrypt|decrypt|rewrap)$/.test(url)) body = url.endsWith('/decrypt') ? { plaintext: 'Zml4dHVyZS1wbGFpbg==', version: 2 } : { ciphertext: 'owt1:fixture-result', version: 2 };
      else if (call.method === 'GET' && Object.hasOwn(routes, url)) body = routes[url];
      else { unexpected.push(call); status = 404; body = { error: 'Unexpected fixture request: ' + call.method + ' ' + url }; }
      return { ok: status < 400, status, text: async () => JSON.stringify(body) };
    },
  });
  context.window = context;
  const ui = {
    document, calls, clipboard, storage, history,
    run(code) { return vm.runInContext(code, context, { timeout: 1000 }); },
    el(id) { const el = document.getElementById(id); assert.ok(el, 'missing rendered element #' + id); return el; },
    async settle() { for (let n = 0; n < 80; n++) await Promise.resolve(); assert.deepEqual(unexpected, [], 'all requests have fixture responses'); },
    async invoke(code) { await this.run(code); await this.settle(); },
    button(root, pattern) { return root.querySelectorAll('button').find(el => visible(el) && !el.disabled && pattern.test((el.getAttribute('aria-label') || el.textContent).trim())); },
    field(pattern, root = this.el('modal')) {
      const fields = root.querySelectorAll('input,textarea,select');
      const field = fields.find(el => pattern.test(el.getAttribute('aria-label') || root.querySelectorAll('label').filter(l => l.getAttribute('for') === el.id || l.contains(el)).map(l => l.textContent).join(' ')));
      assert.ok(field, 'missing labelled field ' + pattern); return field;
    },
    async click(el) {
      assert.ok(el, 'requested button exists'); assert.ok(visible(el) && !el.disabled, 'button is interactive'); el.focus();
      context.__target = el; context.__event = { type: 'click', target: el, preventDefault() {} };
      if (el.getAttribute('onclick')) await this.run(`(async function(event){${el.getAttribute('onclick')}}).call(__target,__event)`);
      else if (el.onclick) await el.onclick(context.__event);
      el.dispatchEvent(context.__event); await this.settle();
    },
    async change(el, value) {
      el.value = value; context.__target = el;
      if (el.getAttribute('onchange')) await this.run(`(async function(){${el.getAttribute('onchange')}}).call(__target)`);
      el.dispatchEvent({ type: 'change' }); await this.settle();
    },
    writes() { return calls.filter(c => c.method !== 'GET'); },
    flushTimers() { for (const fn of timers.splice(0)) fn(); },
    async access() { await this.invoke("nav('access')"); },
  };
  vm.runInContext(i18nSource, context, { filename: 'i18n.js', timeout: 1000 });
  vm.runInContext(script, context, { filename: 'console-inline.js', timeout: 1000 });
  // The merged console hides the shell until sign-in; these tests start inside it.
  document.getElementById('shell').style.display = 'grid';
  await ui.settle();
  assert.equal(ui.run('ORG'), 'org-a', 'full inline console startup selected the fixture workspace');
  if (opts.requireProducts !== false) for (const name of functions) assert.equal(ui.run(`typeof ${name}`), 'function', `${name} must implement the product console contract`);
  return ui;
}
function writesTo(ui, url) { return ui.writes().filter(c => c.url === url); }
function noClientPersistence(ui) { assert.deepEqual(ui.storage, [], 'product values never enter browser storage'); assert.deepEqual(ui.history, [], 'product values never enter history'); assert.deepEqual(ui.clipboard, [], 'clipboard writes require explicit user action'); }
function safeMarkup(root) { assert.equal(root.querySelectorAll('script,img,iframe,svg').length, 0, 'user strings cannot introduce executable markup'); }
function labelledModal(ui) {
  const m = ui.el('modal'); assert.equal(m.getAttribute('role'), 'dialog'); assert.equal(m.getAttribute('aria-modal'), 'true');
  assert.ok(m.getAttribute('aria-label') || m.getAttribute('aria-labelledby') || m.querySelector('h3'), 'modal has a title');
  for (const el of m.querySelectorAll('input,textarea,select').filter(el => visible(el) && el.getAttribute('type') !== 'hidden')) {
    assert.ok(el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || m.querySelectorAll('label').some(l => l.getAttribute('for') === el.id || l.contains(el)), 'every form field has a label');
  }
}
function fillRequest(ui) { ui.field(/title/i).value = 'Cross-environment release'; ui.field(/operations|changes|json/i).value = JSON.stringify(changes); }
async function transitForm(ui, action) {
  await ui.invoke("productTransitModal('key-a')");
  await ui.change(ui.field(/action|operation/i), action);
  ui.field(/context/i).value = 'billing:fixture';
  ui.field(/input|plaintext|ciphertext/i).value = action === 'encrypt' ? 'Zml4dHVyZQ==' : 'owt1:fixture-input';
}

test('the full inline console compiles and starts with the DOM and HTTP fixture', async () => {
  const ui = await consoleUI({ requireProducts: false });
  assert.equal(ui.el('pagetitle').textContent, 'Apps'); assert.deepEqual(ui.writes(), []);
});

test('Members & access adds the three product sections without changing navigation', async () => {
  const ui = await consoleUI(); const nav = ui.document.querySelectorAll('.navbtn').map(el => el.textContent);
  await ui.access();
  assert.equal(ui.el('pagetitle').textContent, 'Members & access');
  for (const heading of ['Members', 'Machine identities', 'Batched change requests', 'Workload trust', 'Transit encryption']) assert.ok(ui.el('view').textContent.includes(heading), 'section ' + heading);
  assert.deepEqual(ui.document.querySelectorAll('.navbtn').map(el => el.textContent), nav);
  for (const url of ['/api/orgs/org-a/change-requests', '/api/orgs/org-a/identities', '/api/orgs/org-a/transit/keys']) assert.ok(ui.calls.some(c => c.method === 'GET' && c.url === url), url);
  assert.ok(ui.el('view').textContent.includes(request.title)); assert.ok(ui.el('view').textContent.includes('7'));
  assert.ok(ui.button(ui.el('view'), /^New change request$/i)); assert.ok(ui.button(ui.el('view'), /^Review$/i));
  assert.ok(!ui.calls.some(c => c.url === '/api/change-requests/request-a'), 'list is metadata only');
  assert.ok(!ui.el('view').textContent.includes('fixture-before')); noClientPersistence(ui);
});

test('new change request submits structured operations for multiple environments', async () => {
  const ui = await consoleUI(); await ui.access(); await ui.click(ui.button(ui.el('view'), /^New change request$/i));
  labelledModal(ui); fillRequest(ui); await ui.invoke('saveProductRequest()');
  assert.deepEqual(writesTo(ui, '/api/orgs/org-a/change-requests'), [{ method: 'POST', url: '/api/orgs/org-a/change-requests', body: { title: 'Cross-environment release', changes } }]);
  assert.ok(!ui.writes().some(c => /\/secrets$|\/(approve|apply)$/.test(c.url)), 'create neither deploys nor approves'); noClientPersistence(ui);
});

test('Review loads before and after values, preserves sealed redaction, and escapes user strings', async () => {
  const unsafe = '<img src=x onerror="fixtureAttack()">';
  const review = clone(detail); review.title = unsafe; review.changes[0].items[0].after.value = unsafe;
  const ui = await consoleUI({ request: { ...request, title: unsafe }, detail: review, identityName: unsafe });
  await ui.access(); safeMarkup(ui.el('view')); await ui.click(ui.button(ui.el('view'), /^Review$/i));
  assert.ok(ui.calls.some(c => c.method === 'GET' && c.url === '/api/change-requests/request-a'));
  labelledModal(ui); const m = ui.el('modal'); assert.ok(m.textContent.includes('fixture-before')); assert.ok(m.textContent.includes(unsafe));
  assert.match(m.textContent, /before/i); assert.match(m.textContent, /after/i); assert.match(m.textContent, /sealed|redact/i); safeMarkup(m);
  assert.ok(!/payload_enc|value_enc/.test(m.innerHTML), 'no hidden raw payload is rendered');
  assert.ok(!ui.button(m, /Edit revision/i), 'a nonauthor cannot edit'); noClientPersistence(ui);
});

test('only the author edits a revision and sends its expected revision without approving it', async () => {
  const ui = await consoleUI({ uid: 'author-a' }); await ui.access(); await ui.invoke("productRequestModal('request-a')");
  const edit = ui.button(ui.el('modal'), /Edit revision/i) || ui.button(ui.el('view'), /Edit revision/i); await ui.click(edit);
  fillRequest(ui); await ui.invoke('saveProductRequest()');
  assert.deepEqual(writesTo(ui, '/api/change-requests/request-a'), [{ method: 'PUT', url: '/api/change-requests/request-a', body: { title: 'Cross-environment release', changes, revision: 7 } }]);
  assert.ok(!ui.writes().some(c => /\/(approve|apply)$/.test(c.url))); noClientPersistence(ui);
});

for (const [action, status] of [['approve', 'pending'], ['apply', 'approved'], ['reject', 'pending']]) {
  test(`${action} is an explicit separate action with the reviewed revision`, async () => {
    const ui = await consoleUI({ request: { ...request, status }, detail: { ...detail, status } }); await ui.access(); await ui.invoke("productRequestModal('request-a')");
    const pattern = new RegExp('^' + action + '(?:\\s|$)', 'i');
    await ui.click(ui.button(ui.el('modal'), pattern) || ui.button(ui.el('view'), pattern));
    assert.deepEqual(ui.writes(), [{ method: 'POST', url: `/api/change-requests/request-a/${action}`, body: { revision: 7 } }], 'one click never chains approval into apply');
  });
}

test('request conflicts and invalid JSON are visible and never retry with another revision', async () => {
  const ui = await consoleUI({ intercept: call => call.url.endsWith('/approve') ? { status: 409, body: { error: 'fixture revision conflict' } } : null });
  await ui.access(); await ui.invoke("productRequestAction('request-a',7,'approve')");
  assert.match(ui.el('toasts').textContent + ui.el('view').textContent + ui.el('modal').textContent, /fixture revision conflict/);
  assert.equal(ui.writes().length, 1); assert.equal(ui.writes()[0].body.revision, 7);
  await ui.invoke('productRequestModal()'); ui.field(/title/i).value = 'Invalid'; ui.field(/operations|changes|json/i).value = '{';
  const before = ui.writes().length; await ui.invoke('saveProductRequest()'); assert.equal(ui.writes().length, before, 'malformed JSON never reaches API');
  assert.match(ui.el('toasts').textContent + ui.el('modal').textContent, /json|invalid|unexpected|syntax/i);
});

test('workload trust uses an existing identity, explicit environment and public claim policy', async () => {
  const ui = await consoleUI(); await ui.access(); await ui.invoke("productTrustModal('identity-a')"); labelledModal(ui);
  const env = ui.field(/environment/i); assert.equal(env.value, '', 'environment selection is explicit, not a current-environment default'); env.value = 'env-b';
  const jwks = { keys: [{ kty: 'EC', crv: 'P-256', kid: 'fixture', x: 'fixture-x', y: 'fixture-y' }] };
  ui.field(/issuer/i).value = trust.issuer; ui.field(/audience/i).value = trust.audience; ui.field(/subject/i).value = trust.subject;
  ui.field(/ttl|lifetime/i).value = '300'; ui.field(/scopes/i).value = 'secrets:read'; ui.field(/jwks/i).value = JSON.stringify(jwks);
  ui.field(/bound claims/i).value = JSON.stringify(trust.bound_claims); await ui.invoke('saveProductTrust()');
  assert.deepEqual(writesTo(ui, '/api/orgs/org-a/identities/identity-a/workload-trust'), [{ method: 'POST', url: '/api/orgs/org-a/identities/identity-a/workload-trust', body: { issuer: trust.issuer, audience: trust.audience, subject: trust.subject, env_id: 'env-b', scopes: ['secrets:read'], ttl: 300, jwks, bound_claims: trust.bound_claims } }]);
  assert.ok(!ui.calls.some(c => /\/login$/.test(c.url)), 'console never exchanges a JWT or mints a workload token');
  assert.ok(!ui.el('modal').querySelectorAll('input,textarea').some(el => /jwt|client.secret/i.test(el.id + ' ' + (el.getAttribute('aria-label') || '')))); noClientPersistence(ui);
});

test('workload trust list and revoke stay on the selected existing identity', async () => {
  const ui = await consoleUI(); await ui.access(); await ui.invoke("productTrustModal('identity-a')");
  assert.ok(ui.calls.some(c => c.method === 'GET' && c.url === '/api/orgs/org-a/identities/identity-a/workload-trust'));
  assert.ok((ui.el('modal').textContent + ui.el('view').textContent).includes(trust.issuer));
  await ui.invoke("revokeProductTrust('identity-a','trust-a')");
  assert.equal(writesTo(ui, '/api/orgs/org-a/identities/identity-a/workload-trust/trust-a')[0]?.method, 'DELETE');
  assert.ok(!ui.writes().some(c => c.url === '/api/orgs/org-a/identities'), 'trust never creates a replacement identity');
});

test('nonadmin members have no workload trust or transit key administration controls', async () => {
  const ui = await consoleUI({ role: 'developer' }); await ui.access();
  const controls = ui.el('view').querySelectorAll('button').filter(el => visible(el) && !el.disabled);
  assert.ok(!controls.some(el => /productTrustModal|revokeProductTrust/.test(el.getAttribute('onclick') || '')), 'trust controls require admin');
  assert.ok(!controls.some(el => /create.*key|rotate|revoke.*trust|new.*trust/i.test(el.textContent)), 'management controls require admin');
});

test('transit key creation and rotation use workspace key endpoints', async () => {
  const ui = await consoleUI(); await ui.access();
  await ui.click(ui.button(ui.el('view'), /^(?:New|Create) (?:transit )?key$/i)); labelledModal(ui);
  ui.field(/name/i).value = 'fixture-key'; await ui.click(ui.button(ui.el('modal'), /^(?:Create|Save)(?: key)?$/i));
  assert.deepEqual(writesTo(ui, '/api/orgs/org-a/transit/keys'), [{ method: 'POST', url: '/api/orgs/org-a/transit/keys', body: { name: 'fixture-key' } }]);
  const rotate = ui.button(ui.el('view'), /^Rotate\b/i); await ui.click(rotate);
  assert.equal(writesTo(ui, '/api/orgs/org-a/transit/keys/key-a/rotate')[0]?.method, 'POST');
});

for (const action of ['encrypt', 'decrypt', 'rewrap']) {
  test(`transit ${action} sends only its operation input and never auto-copies the result`, async () => {
    const ui = await consoleUI(); await ui.access(); await transitForm(ui, action); labelledModal(ui); await ui.invoke('runProductTransit()');
    const body = action === 'encrypt' ? { plaintext: 'Zml4dHVyZQ==', context: 'billing:fixture' } : { ciphertext: 'owt1:fixture-input', context: 'billing:fixture' };
    assert.deepEqual(ui.writes(), [{ method: 'POST', url: `/api/orgs/org-a/transit/keys/key-a/${action}`, body }]);
    const output = ui.el('modal').textContent + ui.el('modal').querySelectorAll('textarea,input').map(el => el.value).join(' ');
    assert.ok(output.includes(action === 'decrypt' ? 'Zml4dHVyZS1wbGFpbg==' : 'owt1:fixture-result'), 'operation result is visible');
    if (action === 'rewrap') assert.ok(!output.includes('Zml4dHVyZS1wbGFpbg=='), 'rewrap result never contains plaintext');
    noClientPersistence(ui);
  });
}

test('late product list and review responses cannot replace another workspace', async () => {
  let release; const pending = new Promise(resolve => { release = resolve; }); let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const ui = await consoleUI({ intercept: async call => {
    if (call.url === '/api/orgs/org-a/change-requests') { entered(); await pending; return { body: [{ ...request, title: 'STALE WORKSPACE A' }] }; }
    return null;
  } });
  const oldRender = ui.run("nav('access')"); await started;
  await ui.invoke("ORG='org-b'; nav('access')"); const activeView = ui.el('view').innerHTML;
  release(); await oldRender; await ui.settle(); assert.equal(ui.el('view').innerHTML, activeView, 'late list cannot overwrite workspace B');
  let releaseReview; const reviewPending = new Promise(resolve => { releaseReview = resolve; }); let reviewEntered;
  const reviewStarted = new Promise(resolve => { reviewEntered = resolve; });
  const second = await consoleUI({ intercept: async call => {
    if (call.url === '/api/change-requests/request-a') { reviewEntered(); await reviewPending; return { body: { ...detail, title: 'STALE REVIEW A' } }; }
    return null;
  } });
  await second.access(); const opening = second.run("productRequestModal('request-a')"); await reviewStarted;
  await second.invoke("ORG='org-b'; nav('access')"); await second.invoke("modal('<h3>Workspace B dialog</h3>','Workspace B')");
  const activeModal = second.el('modal').innerHTML; releaseReview(); await opening; await second.settle();
  assert.equal(second.el('modal').innerHTML, activeModal, 'late review cannot replace an active dialog in B');
});

for (const kind of ['request', 'trust', 'transit']) {
  test(`${kind} modal cannot submit into a newly selected workspace`, async () => {
    const ui = await consoleUI(); await ui.access();
    if (kind === 'request') { await ui.invoke('productRequestModal()'); fillRequest(ui); }
    if (kind === 'trust') await ui.invoke("productTrustModal('identity-a')");
    if (kind === 'transit') await transitForm(ui, 'encrypt');
    const oldModal = ui.el('modal'); await ui.invoke("ORG='org-b'; nav('access')");
    await ui.invoke(kind === 'request' ? 'saveProductRequest()' : kind === 'trust' ? 'saveProductTrust()' : 'runProductTransit()');
    assert.deepEqual(ui.writes(), [], 'a stale modal must be refused rather than retargeted'); noClientPersistence(ui);
    assert.ok(oldModal, 'the original modal existed before the workspace switch');
  });
}

test('product dialogs reuse keyboard focus trapping, Escape dismissal and field labels', async () => {
  const ui = await consoleUI(); await ui.access(); const opener = ui.button(ui.el('view'), /^New change request$/i); await ui.click(opener);
  labelledModal(ui); ui.flushTimers();
  const fields = ui.el('modal').querySelectorAll('input,textarea,select,button').filter(el => !el.disabled);
  assert.equal(ui.document.activeElement, fields[0]); fields.at(-1).focus();
  const tab = { type: 'keydown', key: 'Tab', shiftKey: false }; ui.document.activeElement.dispatchEvent(tab);
  assert.equal(ui.document.activeElement, fields[0]); assert.equal(tab.defaultPrevented, true);
  ui.document.activeElement.dispatchEvent({ type: 'keydown', key: 'Escape' });
  assert.ok(!ui.el('modalwrap').classList.contains('show')); assert.equal(ui.document.activeElement, opener); assert.deepEqual(ui.writes(), []);
});
