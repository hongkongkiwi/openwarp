'use strict';

// Run with node --test crates/server/tests/ui.test.cjs. No server or browser is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
const i18nSource = fs.readFileSync(path.join(__dirname, '../src/i18n.js'), 'utf8');
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
  get childNodes() { return this.children; }
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
    const selfClosing = /\/\s*>$/.test(token);
    if (!selfClosing && !/^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/i.test(tag)) stack.push(el);
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
  document.documentElement = document.querySelector('html');
  document.activeElement = document.body;
  // A remembered workspace keeps the existing flows inside the shell. The
  // picker tests clear it to exercise the choice itself.
  const calls = [], unexpected = [], confirmations = [], timers = [], store = { 'ow.org.fixture@example.invalid': 'org-a', ...opts.store };
  const media = { matches: !!opts.dark, listeners: [], addEventListener(type, fn) { if (type === 'change') this.listeners.push(fn); } };
  const responses = {
    '/api/auth/providers': { google: false, github: false, saml: true, signups: 'open' },
    '/api/instance': { instance_owner: false },
    '/api/instance/edition': { tier: 'self-hosted', enterprise: false, customer: null, expires_at: null, development: false, warning: null },
    '/api/me': { email: 'fixture@example.invalid' },
    '/api/orgs': [{ id: 'org-a', name: 'First org', role: 'admin', members: 3 }, { id: 'org-b', name: 'Second org', role: 'admin', members: 1 }],
    '/api/orgs/org-a/apps': [{ id: 'app-a', name: 'First app' }, { id: 'app-b', name: 'Second app' }],
    '/api/orgs/org-a/settings': { ip_allowlist: '', oidc_issuer: '', oidc_client_id: '', oidc_redirect_uri: '', oidc_client_secret_set: false, oidc_auto_provision: false, oidc_allowed_domains: '', audit_webhook: '' },
    '/api/orgs/org-a/saml': { configured: false },
    // Fixture workspaces hold every grant; a test that wants an ungranted
    // surface overrides this entry.
    '/api/orgs/org-a/features': { compiled: ['saml', 'scim', 'pki', 'ssh-ca', 'transit', 'workload-identity', 'change-requests', 'ldap'], granted: ['saml', 'scim', 'pki', 'ssh-ca', 'transit', 'workload-identity', 'change-requests', 'ldap'] },
    '/api/orgs/org-b/features': { compiled: ['saml', 'scim', 'pki', 'ssh-ca', 'transit', 'workload-identity', 'change-requests', 'ldap'], granted: ['saml', 'scim', 'pki', 'ssh-ca', 'transit', 'workload-identity', 'change-requests', 'ldap'] },
    '/api/orgs/org-a/pki/cas': [],
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
    '/api/orgs/org-a/webhooks': [{ id: 'hook-1', name: '<script>fixture</script>', url: 'https://receiver.example.invalid/events', app_id: 'app-a', events: ['secret.update'], enabled: true }, { id: 'hook/workspace', name: 'Workspace hook', url: 'https://receiver.example.invalid/workspace', app_id: '', events: ['*'], enabled: false }],
    '/api/orgs/org-b/webhooks': [],
    '/api/envs/env-a/integrations': [{ id: 'integration/ #', kind: 'webhook', name: 'Encoded integration' }],
    '/api/envs/env-a/rotations': [],
    '/api/envs/env-a/dynamic': [],
    '/api/integrations/integration%2F%20%23/webhooks': [{ id: 'incoming/ #', name: '<img src=x onerror=bad()>', enabled: true }],
    '/api/incoming-webhooks/incoming%2F%20%23/receipts?limit=25&offset=0': [{ id: 'receipt/ #', message_id: 'message-encoded', status: 'queued', attempts: 1, body: 'RAW_REQUEST_BODY', response_body: 'RAW_RESPONSE_BODY', headers: { authorization: 'RAW_AUTHORIZATION' } }],
    'PATCH /api/incoming-webhooks/incoming%2F%20%23': { ok: true },
    'POST /api/incoming-webhooks/incoming%2F%20%23/reauthorize': { id: 'incoming/ #', enabled: true },
    'PATCH /api/webhooks/hook-1': { id: 'hook-1', enabled: false },
    'POST /api/integrations/integration%2F%20%23/webhooks': { id: 'incoming-new', secret: 'whsec_created-incoming', url: 'https://console.invalid/hooks/integrations/incoming-new' },
    '/api/webhooks/hook-1/deliveries?limit=25&offset=0': [{ id: 'delivery-1', event_id: 'event-1', status: 'dead_lettered', attempts: 5, http_status: 503, duration_ms: 25, updated_at: 1800000000, error_code: 'http_error' }],
    '/api/integrations/integration-1/webhooks': [{ id: 'incoming-1', name: 'Deployment trigger', enabled: true, url: 'https://console.invalid/hooks/integrations/incoming-1' }],
    '/api/incoming-webhooks/incoming-1/receipts?limit=25&offset=0': [{ id: 'receipt-1', message_id: 'message-1', status: 'queued', attempts: 0 }],
    '/api/orgs/org-a/ssh/cas': [],
    '/api/orgs/org-a/invites': [],
    '/api/orgs/org-a/emergency': { locked: false },
    '/api/orgs/org-b/emergency': { locked: false },
    '/api/apps/app-a/emergency': { locked: false, direct_locked: false, workspace_locked: false },
    '/api/apps/app-b/emergency': { locked: false, direct_locked: false, workspace_locked: false },
    '/api/apps/app-c/emergency': { locked: false, direct_locked: false, workspace_locked: false },
    '/api/ssh/cas/ca-ssh-1': { id: 'ca-ssh-1', name: 'ssh-ca', public_key: 'ssh-ed25519 AAAAC3Nza', fingerprint: 'SHA256:fixture', allow_forwarding: false, sshd: 'TrustedUserCAKeys /etc/ssh/openwarp/ca.pub', grants: [{ role: 'developer', principals: ['web-*'], max_ttl: 900 }] },
    '/api/ssh/cas/ca-ssh-1/certs': [{ id: 'ssh-cert-1', key_id: 'openwarp:ssh-cert-1', principal: 'web-1', serial: 7, revoked: 0, valid_before: 1800000000, cert_type: 'user' }],
    '/api/ssh/cas/ca-ssh-1/hosts': [{ id: 'host-1', hostname: 'db-1.internal', fingerprint: 'SHA256:hostkey' }],
    ...opts.responses,
  };
  const session = new Map();
  const context = vm.createContext({
    document, console, URL, TextDecoder, TextEncoder, matchMedia: () => media,
    localStorage: {
      getItem: key => (Object.hasOwn(store, key) ? store[key] : ''),
      setItem: (key, value) => { store[key] = String(value); },
      removeItem: key => { delete store[key]; },
    },
    sessionStorage: { getItem: key => session.get(key) ?? null, setItem: (key, value) => session.set(key, String(value)), removeItem: key => session.delete(key) },
    navigator: { clipboard: { writeText: async () => {} }, languages: opts.languages, language: opts.languages && opts.languages[0] },
    location: { origin: 'http://console.invalid', hash: '', pathname: '/', reload() {} },
    history: { replaceState() {} },
    setTimeout: fn => { timers.push(fn); return timers.length; }, clearTimeout() {},
    setInterval: () => 1, clearInterval() {},
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
      if (opts.fetchOverride) { const answer = opts.fetchOverride(call); if (answer !== undefined) return { ok: true, status: 200, text: async () => JSON.stringify(await answer) }; }
      if (options.method === 'PUT' && /^\/api\/envs\/[^/]+\/secrets$/.test(url)) body = { deployed: call.body.secrets.length };
      else if (options.method === 'POST' && /^\/api\/envs\/[^/]+\/secrets\/reuse-check$/.test(url)) {
        if (opts.reuseFail) return { ok: false, status: 500, text: async () => JSON.stringify({ error: 'preflight unavailable' }) };
        body = { enabled: true, matches: (call.body.exclude || []).includes('saved-secret') ? [] : reuse };
      }
      else if (options.method === 'PUT' && url === '/api/apps/app-a/settings') body = { ok: true };
      else if (options.method === 'PUT' && url === '/api/orgs/org-a/settings') body = { ok: true };
      else if (options.method === 'DELETE' && url === '/api/secrets/saved-secret') body = {};
      else if (options.method === 'DELETE' && /^\/api\/me\/sessions\/[^/]+$/.test(url)) body = { revoked: url.split('/').pop(), current: false };
      // These routes return success so a forbidden staged-row request fails an assertion, not the harness.
      else if (/^\/api\/secrets\/new-[^/]+(?:\/history)?$/.test(url)) body = url.endsWith('/history') ? [] : {};
      else if (options.method === 'POST' && url === '/api/auth/ldap') body = { mfa_required: true, mfa_token: 'mfa-1' };
      else if (options.method === 'POST' && url === '/api/auth/mfa') body = { token: 'session-token' };
      else if (options.method === 'POST' && url === '/api/orgs/org-a/ssh/cas') body = { id: 'ca-ssh-1', name: 'ssh-ca', public_key: 'ssh-ed25519 AAAAC3Nza', fingerprint: 'SHA256:fixture', sshd: 'TrustedUserCAKeys /etc/ssh/openwarp/ca.pub' };
      else if (options.method === 'PUT' && url === '/api/ssh/cas/ca-ssh-1/grants') body = { ca_id: 'ca-ssh-1', roles: call.body.grants.map(g => g.role) };
      else if (options.method === 'POST' && url === '/api/ssh/certs/ssh-cert-1/revoke') body = { revoked: 'ssh-cert-1' };
      else if (options.method === 'POST' && url === '/api/ssh/cas/ca-ssh-1/hosts') body = { id: 'host-2', hostname: call.body.hostname, fingerprint: 'SHA256:newhost' };
      else if (options.method === 'DELETE' && url === '/api/ssh/cas/ca-ssh-1/hosts/host-1') body = { deleted: 'host-1' };
      else if (options.method === 'POST' && /\/webhooks\/hook-1\/rotate$/.test(url)) body = { id: 'hook-1', secret: 'whsec_fixture-one-time-key' };
      else if (options.method === 'POST' && url === '/api/webhook-deliveries/delivery-1/retry') body = { ok: true };
      else if (Object.hasOwn(responses, options.method + ' ' + url)) body = responses[options.method + ' ' + url];
      else if (opts.pki && options.method === 'POST' && url === '/api/pki/cas/ca-a/devices/codes') body = { codes: call.body.device_ids.map(id => id === 'dev-b' ? { id, error: 'device no longer available' } : { id, name: 'sensor-a', code: 'test-code', nonce: 'test-nonce', expires_at: 1900000000 }) };
      else if (options.method === 'GET' && opts.responses && Object.hasOwn(opts.responses, url)) body = opts.responses[url];
      else if (options.method === 'GET' && Object.hasOwn(responses, url)) body = responses[url];
      else { unexpected.push(call); throw new Error('Unexpected fixture request: ' + options.method + ' ' + url); }
      return { ok: true, status: 200, text: async () => JSON.stringify(body) };
    },
  });
  const ui = {
    document, calls, confirmations, confirm: false, store, media,
    systemDark(dark) { media.matches = dark; for (const fn of media.listeners) fn({ matches: dark }); },
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
  // Browser load order: the i18n runtime executes before the inline console script.
  vm.runInContext(i18nSource, context, { filename: 'i18n.js', timeout: 1000 });
  vm.runInContext(script, context, { filename: 'console-inline.js', timeout: 1000 });
  if (!opts.manualBoot) { await ui.invoke('enterApp()'); await ui.invoke("openApp('app-a')"); }
  calls.length = 0;
  return ui;
}

test('Webhooks navigation lists workspace and app scopes and follows the selected workspace', async () => {
  const ui = await consoleUI();
  await ui.click(ui.document.querySelector('[data-nav="webhooks"]'));
  assert.equal(ui.el('pagetitle').textContent, 'Webhooks');
  assert.ok(ui.calls.some(c => c.url === '/api/orgs/org-a/webhooks'));
  const rows = ui.el('view').querySelectorAll('tbody tr');
  assert.ok(rows.some(r => r.textContent.includes('First app') && r.textContent.includes('Enabled')));
  assert.ok(rows.some(r => r.textContent.includes('Workspace hook') && r.textContent.includes('Workspace') && r.textContent.includes('Paused')));
  await ui.click(ui.button(ui.el('view'), /^Create outgoing webhook$/));
  assert.deepEqual(ui.el('hook-app').querySelectorAll('option').map(o => [o.value, o.textContent]), [['', 'Entire workspace'], ['app-a', 'First app'], ['app-b', 'Second app']]);
  await ui.invoke("closeModal(); ORG='org-b'; nav('webhooks')");
  assert.ok(ui.calls.some(c => c.url === '/api/orgs/org-b/webhooks'));
  assert.match(ui.el('view').textContent, /No outgoing webhooks/);
  assert.ok(!ui.el('view').textContent.includes('Workspace hook'));
});

test('outgoing webhook names are escaped and delivery history renders metadata only', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('webhooks')");
  assert.ok(ui.el('view').textContent.includes('<script>fixture</script>'));
  assert.equal(ui.el('view').querySelector('script'), null);
  await ui.click(ui.button(ui.el('view'), /^Deliveries$/));
  const history = ui.el('hook-history');
  for (const value of ['event-1', 'dead_lettered', '5', '503', '25 ms', 'http_error']) assert.ok(history.textContent.includes(value), value);
  assert.ok(ui.button(history, /^Retry delivery$/));
  assert.match(history.textContent, /deduplicate event IDs/);
  assert.deepEqual(ui.writes(), []);
});

test('declining webhook rotation, test and delivery replay makes no network requests', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('webhooks')");
  await ui.click(ui.button(ui.el('view'), /^Deliveries$/));
  ui.calls.length = 0;
  await ui.click(ui.button(ui.el('view'), /^Rotate key$/));
  await ui.click(ui.button(ui.el('view'), /^Send test$/));
  await ui.click(ui.button(ui.el('hook-history'), /^Retry delivery$/));
  assert.equal(ui.confirmations.length, 3);
  assert.match(ui.confirmations[0], /existing key stops working/);
  assert.match(ui.confirmations[2], /already have processed/);
  assert.deepEqual(ui.calls, []);
});

test('one-time webhook keys are scrubbed by Escape, backdrop and explicit close', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('webhooks')");
  ui.confirm = true;
  for (const dismissal of ['Escape', 'backdrop', 'explicit']) {
    await ui.click(ui.button(ui.el('view'), /^Rotate key$/));
    const input = ui.el('hook-key');
    assert.equal(input.value, 'whsec_fixture-one-time-key');
    assert.equal(input.getAttribute('type'), 'password');
    if (dismissal === 'Escape') ui.key('Escape');
    else if (dismissal === 'backdrop') ui.el('modalwrap').dispatchEvent({ type: 'click', target: ui.el('modalwrap') });
    else await ui.click(ui.button(ui.el('modal'), /^I saved the key$/));
    assert.equal(input.value, '', dismissal + ' must clear retained input references');
    assert.equal(ui.document.querySelector('#hook-key'), null);
    assert.ok(!ui.el('modalwrap').classList.contains('show'));
    assert.ok(!ui.document.textContent.includes('whsec_fixture-one-time-key'));
    assert.ok(!ui.document.innerHTML.includes('whsec_fixture-one-time-key'));
  }
});

test('integration incoming hooks encode IDs and pause only the selected integration trigger', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('integrations')");
  await ui.click(ui.button(ui.el('view'), /^Incoming hooks$/));
  assert.ok(ui.calls.some(c => c.url === '/api/integrations/integration%2F%20%23/webhooks'));
  assert.ok(ui.el('modal').textContent.includes('<img src=x onerror=bad()>'));
  assert.equal(ui.el('modal').querySelector('img'), null);
  await ui.click(ui.button(ui.el('modal'), /^Receipts$/));
  const receipts = ui.el('incoming-receipts');
  assert.match(receipts.textContent, /message-encoded/);
  assert.match(receipts.textContent, /queued/);
  for (const forbidden of ['RAW_REQUEST_BODY', 'RAW_RESPONSE_BODY', 'RAW_AUTHORIZATION']) assert.ok(!ui.el('modal').innerHTML.includes(forbidden));
  assert.equal(ui.button(receipts, /^Retry delivery$/), undefined);
  await ui.click(ui.button(ui.el('modal'), /^Pause$/));
  assert.deepEqual(ui.writes(), [{ method: 'PATCH', url: '/api/incoming-webhooks/incoming%2F%20%23', body: { enabled: false } }]);
  assert.equal(ui.calls.at(-1).url, '/api/integrations/integration%2F%20%23/webhooks');
});

test('incoming webhook creation keeps the integration ID and shows its key only once', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('integrations')");
  await ui.click(ui.button(ui.el('view'), /^Incoming hooks$/));
  ui.el('incoming-name').value = '  Deploy selected integration  ';
  await ui.click(ui.button(ui.el('modal'), /^Create incoming webhook$/));
  assert.deepEqual(ui.writes(), [{ method: 'POST', url: '/api/integrations/integration%2F%20%23/webhooks', body: { name: 'Deploy selected integration', enabled: true } }]);
  assert.equal(ui.el('hook-key').value, 'whsec_created-incoming');
  assert.equal(ui.el('hook-endpoint').value, 'https://console.invalid/hooks/integrations/incoming-new');
  await ui.click(ui.button(ui.el('modal'), /^I saved the key$/));
  assert.equal(ui.document.querySelector('#hook-key'), null);
  assert.ok(!ui.document.innerHTML.includes('whsec_created-incoming'));
});

test('incoming reauthorization requires consent and reloads only the selected integration without exposing keys', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('integrations')");
  await ui.click(ui.button(ui.el('view'), /^Incoming hooks$/));
  ui.calls.length = 0;
  await ui.click(ui.button(ui.el('modal'), /^Reauthorize$/));
  assert.deepEqual(ui.calls, [], 'refusing consent must make no API request');
  assert.equal(ui.confirmations.length, 1);
  assert.match(ui.confirmations[0], /current credential/);
  assert.match(ui.confirmations[0], /Pending sync requests are cancelled/);
  assert.match(ui.confirmations[0], /URL and signing key stay the same/);
  ui.confirm = true;
  await ui.click(ui.button(ui.el('modal'), /^Reauthorize$/));
  assert.deepEqual(ui.calls, [
    { method: 'POST', url: '/api/incoming-webhooks/incoming%2F%20%23/reauthorize', body: {} },
    { method: 'GET', url: '/api/integrations/integration%2F%20%23/webhooks', body: undefined },
  ]);
  assert.equal(ui.document.querySelector('#hook-key'), null);
  assert.equal(ui.document.querySelector('#hook-endpoint'), null);
  assert.ok(!ui.document.innerHTML.includes('whsec_'));
  assert.ok(!ui.el('modal').innerHTML.includes('https://console.invalid/hooks/'));
});

test('outgoing webhook edit preserves explicit app scope and sends only editable fields', async () => {
  const ui = await consoleUI();
  await ui.invoke("nav('webhooks')");
  await ui.click(ui.button(ui.el('view'), /^Edit$/));
  assert.equal(ui.el('hook-app').value, 'app-a');
  ui.el('hook-name').value = '  Revised subscription  ';
  ui.el('hook-url').value = '  https://receiver.example.invalid/revised  ';
  ui.el('hook-events').value = ' secret.deploy, integration.sync, ';
  ui.el('hook-enabled').checked = false;
  ui.calls.length = 0;
  await ui.click(ui.button(ui.el('modal'), /^Save webhook$/));
  assert.deepEqual(ui.writes(), [{ method: 'PATCH', url: '/api/webhooks/hook-1', body: {
    name: 'Revised subscription', url: 'https://receiver.example.invalid/revised',
    app_id: 'app-a', events: ['secret.deploy', 'integration.sync'], enabled: false,
  } }]);
  assert.deepEqual(ui.calls.slice(1).map(c => c.url), ['/api/orgs/org-a/webhooks', '/api/orgs/org-a/apps']);
  assert.equal(ui.document.querySelector('#hook-key'), null);
});

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
      await ui.invoke("switchOrg('org-b')");
      await ui.invoke("switchOrg('org-a')");
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

test('emergency lockdown clears cached secrets, drafts and dialogs and blocks browsing', async () => {
  const ui = await consoleUI();
  await ui.add();
  await ui.invoke("E2E_KIT='private-kit';E2E_DATA['e2e']=[{value:'cached'}];E2E_KEYS['e2e']='key';applyEmergency(true)");
  assert.equal(ui.run('SECRETS.length'), 0);
  assert.equal(ui.run('Object.keys(DRAFTS).length'), 0);
  assert.equal(ui.run('Object.keys(E2E_DATA).length'), 0);
  assert.equal(ui.run('Object.keys(E2E_KEYS).length'), 0);
  assert.equal(ui.run('E2E_KIT'), '');
  assert.equal(ui.el('modal').innerHTML, '');
  assert.ok(hidden(ui.el('deploybar')));
  assert.match(ui.el('emergency-banner').textContent, /Emergency lockdown active/);
  await ui.invoke("nav('integrations')");
  assert.match(ui.el('view').textContent, /Emergency lockdown active/);
  await assert.rejects(ui.run("api('GET','/api/envs/env-a/secrets')"), /emergency lockdown/);
  assert.deepEqual(ui.writes(), []);
});

test('project lockdown leaves metadata readable and blocks secrets and changes', async () => {
  const ui = await consoleUI();
  await ui.invoke("VIEW='settings';$('view').innerHTML='<button>Save settings</button>';PROJECT_DIRECT=true;applyEmergency(false,true)");
  assert.equal(ui.button(ui.el('view'), /^Save settings$/), undefined, 'a newly detected halt must remove existing writable controls');
  await ui.invoke('renderEnv()');
  assert.equal(ui.run('EMERGENCY'), false, 'project state must not become a workspace halt');
  assert.match(ui.el('view').textContent, /Environment names remain visible/);
  assert.match(ui.el('view').textContent, /Development/);
  await ui.invoke("api('GET','/api/apps/app-a/envs')");
  await assert.rejects(ui.run("api('GET','/api/envs/env-a/export')"), /emergency lockdown/);
  await assert.rejects(ui.run("api('PUT','/api/envs/env-a/secrets',{secrets:[]})"), /emergency lockdown/);
  assert.deepEqual(ui.writes(), []);
  await ui.invoke('EMERGENCY_OWNER=false');
  assert.doesNotMatch(ui.run('emergencyCard(true)'), /onclick="confirmEmergency/);
  await ui.invoke('EMERGENCY_OWNER=true');
  assert.match(ui.run('emergencyCard(true)'), /Restore project access/);
  assert.match(ui.run('emergencyCard()'), /Activate workspace lockdown/);
  await ui.invoke('renderSettings()');
  assert.equal(ui.button(ui.el('view'), /^Save settings$/), undefined, 'project lockdown must hide writable workspace settings');
  assert.match(ui.el('view').textContent, /Restore project access/);
  await ui.invoke('applyEmergency(true,true)');
  assert.match(ui.run('emergencyCard(true)'), /workspace lockdown also applies/);
});

test('a sibling project lockdown clears an open AI view without recursive polling', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    'GET /api/orgs/org-a/ai/settings': { status: 403, body: { error: 'a project emergency lockdown is active' } },
  } });
  await ui.invoke("APP=null;ENV=null;VIEW='assistant';AI_REFS=[{key:'private-name'}];AI_PLAN={id:'pending'};$('view').innerHTML='<p>private-name</p>'");
  ui.calls.length = 0;
  await ui.invoke('refreshEmergency()');
  assert.doesNotMatch(ui.el('view').textContent, /private-name/);
  assert.match(ui.el('view').textContent, /Project emergency lockdown active/);
  assert.equal(ui.run('AI_REFS.length'), 0);
  assert.equal(ui.run('AI_PLAN'), null);
  assert.equal(ui.calls.filter(c => c.url === '/api/orgs/org-a/ai/settings').length, 1, 'a single poll must not recursively trigger another probe');
});

test('an ended session removes plaintext and returns to sign-in', async () => {
  const ui = await consoleUI();
  await ui.invoke("E2E_KIT='private-kit';PKI_SELECTED.add('dev-a');PKI_CODE_RESULTS=[{code:'stale'}];PKI_HOOK={ca:'ca-a',render:PKI_RENDER};PKI_ATT={ca:'ca-a',render:PKI_RENDER};applyEmergency(true);sessionEnded()");
  assert.equal(ui.el('shell').style.display, 'none');
  assert.equal(ui.el('auth').style.display, 'grid');
  assert.equal(ui.el('view').innerHTML, '');
  assert.equal(ui.run('E2E_KIT'), '');
  assert.equal(ui.run('AUTH_READY'), false);
  assert.equal(ui.run('PKI_SELECTED.size'), 0);
  assert.equal(ui.run('PKI_CODE_RESULTS.length'), 0);
  assert.equal(ui.run('PKI_HOOK'), null);
  assert.equal(ui.run('PKI_ATT'), null);
  assert.equal(ui.run('EMERGENCY'), false, 'an ended session must not block the next sign-in');
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

test('the SAML sign-in button follows the build, not the workspace grant', async () => {
  // A build that carries SAML keeps the button even when a workspace has not
  // enabled it; the attempt explains why. A build without it has no route, so
  // the button would be dead and is hidden.
  const withSaml = await consoleUI();
  await withSaml.invoke('loadProviders()');
  assert.ok(withSaml.document.getElementById('saml-signin'),
    'the sign-in view always carries the SAML button node');
  assert.notEqual(withSaml.el('saml-signin').style.display, 'none',
    'a build with SAML shows the button regardless of workspace grants');

  const withoutSaml = await consoleUI([saved], [], { responses: {
    '/api/auth/providers': { google: false, github: false, saml: false, signups: 'open' },
  } });
  await withoutSaml.invoke('loadProviders()');
  assert.equal(withoutSaml.el('saml-signin').style.display, 'none',
    'a build without SAML hides the button because the route does not exist');
});

test('a workspace-disabled sign-in method reports a readable reason, not JSON', async () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
  assert.match(source, /saml_not_enabled:'SAML sign-in is not enabled for this workspace\.'/,
    'the sign-in screen must translate the saml_not_enabled code into a sentence');
  assert.match(source, /ldap_not_enabled:'Directory sign-in is not enabled for this workspace\.'/,
    'the sign-in screen must translate the ldap_not_enabled code into a sentence');
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
  assert.ok(ui.el('ssh-ca-out').textContent.includes('SHA256:fixture'), 'the new CA reports its fingerprint');
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
  await ui.invoke("switchOrg('org-b')");
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

test('delayed PKI rendering and minted codes cannot cross workspaces', async () => {
  let releaseMint, releaseRender, holdRender=false;
  const opts={pki:true,responses:{
    '/api/orgs/org-a/pki/cas':[{id:'ca-a',name:'A',kind:'root',certificate:'A-CERT'}],
    '/api/orgs/org-b/pki/cas':[{id:'ca-b',name:'B',kind:'root',certificate:'B-CERT'}],
    '/api/orgs/org-b/settings':{}, '/api/orgs/org-b/saml':{configured:false}, '/api/orgs/org-b/ssh/cas':[],
    '/api/pki/cas/ca-a/devices':[{id:'dev-a',name:'sensor-a'}], '/api/pki/cas/ca-b/devices':[],
    '/api/pki/cas/ca-a/groups':[], '/api/pki/cas/ca-b/groups':[],
    '/api/orgs/org-a/pki/expiring?days=30':{counts:{7:0,14:0,30:0}}, '/api/orgs/org-b/pki/expiring?days=30':{counts:{7:0,14:0,30:0}},
    '/api/pki/cas/ca-a/hook':{url:''}, '/api/pki/cas/ca-b/hook':{url:''},
    '/api/pki/cas/ca-a/attestation':{}, '/api/pki/cas/ca-b/attestation':{},
  },fetchOverride:call=>{
    if(call.url==='/api/pki/cas/ca-a/devices/codes')return new Promise(resolve=>{releaseMint=resolve});
    if(holdRender&&call.url==='/api/orgs/org-a/pki/cas')return new Promise(resolve=>{releaseRender=resolve});
  }};
  const ui=await consoleUI([saved],[],opts);await ui.invoke('renderSettings()');await ui.invoke('selectAllPki()');
  ui.run('pendingMint=mintSelectedPki()');await ui.settle();holdRender=true;ui.run('pendingRender=renderPki()');await ui.settle();
  await ui.invoke("ORG='org-b';renderSettings()");
  releaseRender(opts.responses['/api/orgs/org-a/pki/cas']);await ui.invoke('pendingRender');
  releaseMint({codes:[{id:'dev-a',name:'sensor-a',code:'A-SECRET-CODE',nonce:'a'}]});await ui.invoke('pendingMint');
  assert.equal(ui.run('PKI_CA'),'ca-b');assert.equal(ui.el('pki-codes-out').textContent,'');
  assert.ok(ui.el('pki-download-codes').disabled);assert.ok(!ui.el('view').textContent.includes('A-SECRET-CODE'));
});

test('PKI bulk codes use explicit selection and show partial failures', async () => {
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Root', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/pki/cas/ca-a/devices': [{ id: 'dev-a', name: 'sensor-a' }, { id: 'dev-b', name: 'sensor-b' }],
    '/api/pki/cas/ca-a/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
    '/api/pki/cas/ca-a/hook': { url: '' },
    '/api/pki/cas/ca-a/attestation': { issuer: '', algorithm: 'ES256', required: false },
  } };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  assert.ok(ui.el('pki-mint-selected').disabled);
  await ui.invoke('selectAllPki()');
  assert.equal(ui.el('pki-selection-count').textContent, '2 selected');
  await ui.click(ui.el('pki-mint-selected'));
  const call = ui.calls.find(c => c.url === '/api/pki/cas/ca-a/devices/codes');
  assert.deepEqual(Array.from(call.body.device_ids), ['dev-a', 'dev-b']);
  assert.match(ui.el('pki-codes-out').textContent, /test-code/);
  assert.match(ui.el('pki-codes-out').textContent, /device no longer available/);
  assert.equal(ui.el('pki-download-codes').disabled, false);
  await ui.invoke('clearPkiSelection()');
  assert.equal(ui.el('pki-mint-selected').disabled, true);
  opts.responses['/api/orgs/org-a/pki/cas'] = [{ id: 'ca-b', name: 'Other root', kind: 'root', certificate: 'OTHER PUBLIC CERT' }];
  opts.responses['/api/pki/cas/ca-b/devices'] = [];
  opts.responses['/api/pki/cas/ca-b/groups'] = [];
  opts.responses['/api/pki/cas/ca-b/hook'] = { url: '' };
  opts.responses['/api/pki/cas/ca-b/attestation'] = { issuer: '', algorithm: 'ES256' };
  await ui.invoke("PKI_CODE_RESULTS=[{code:'stale'}];PKI_SELECTED.add('dev-a');renderPki()");
  assert.equal(ui.el('pki-selection-count').textContent, '0 selected');
  assert.equal(ui.el('pki-download-codes').disabled, true);
});

test('PKI device import accepts exported headers, quoted cells and the legacy headerless rows', async () => {
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Root', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/pki/cas/ca-a/devices': [],
    '/api/pki/cas/ca-a/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
    '/api/pki/cas/ca-a/hook': { url: '' },
    '/api/pki/cas/ca-a/attestation': { issuer: '', algorithm: 'ES256', required: false },
  }, fetchOverride: call => call.method === 'POST' && call.url === '/api/pki/cas/ca-a/devices/import'
    ? { created: 2, failed: 0, results: [] } : undefined };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  const rows = JSON.parse(ui.run(`JSON.stringify(parseCsvRows(${JSON.stringify('name,model\r\n"a,b","say ""hi"""\r\n')}))`));
  assert.deepEqual(rows, [['name', 'model'], ['a,b', 'say "hi"']],
    'quoted cells keep commas, newlines and doubled quotes');
  ui.el('pki-import').value = [
    'name,model,hardware_serial,tags,env_id,group_id,sans,cert_days,serial,expires_at,revoked,attested',
    'sensor-1,model-a,S123,"site=a,b",env-9,group-9,"gw.local;192.0.2.10",45,ABC,1900000000,false,false',
    'sensor-2,model-b,S456,site=c,env-9,,"gw2.local,192.0.2.11",30,DEF,1900000000,false,false',
  ].join('\r\n');
  await ui.click(ui.button(ui.el('pki-body'), /Import and mint codes/));
  const call = ui.calls.find(c => c.url === '/api/pki/cas/ca-a/devices/import');
  assert.deepEqual(call.body.devices, [
    { name: 'sensor-1', model: 'model-a', hardware_serial: 'S123', tags: 'site=a,b', env_id: 'env-9', group_id: 'group-9', sans: ['gw.local', '192.0.2.10'], cert_days: 45 },
    { name: 'sensor-2', model: 'model-b', hardware_serial: 'S456', tags: 'site=c', env_id: 'env-9', sans: ['gw2.local', '192.0.2.11'], cert_days: 30 },
  ], 'exported columns map by header and status columns are ignored');
  const legacy = JSON.parse(ui.run(`JSON.stringify(deviceImportRows(${JSON.stringify('sensor-3,model-c,S789,site=d,env-9,gw.local;192.0.2.12,60')}))`));
  assert.deepEqual(legacy, [{ name: 'sensor-3', model: 'model-c', hardware_serial: 'S789', tags: 'site=d', env_id: 'env-9', sans: ['gw.local', '192.0.2.12'], cert_days: 60 }],
    'the previous headerless line format keeps working');
  assert.throws(() => ui.run(`parseCsvRows(${JSON.stringify('"open')})`), /Unterminated quoted CSV cell/);
  assert.throws(() => ui.run(`deviceImportRows(${JSON.stringify('model,tags\nsensor,site=a')})`), /must include a name column/);
  assert.throws(() => ui.run(`deviceImportRows(${JSON.stringify('name,cert_days\nsensor,soon')})`), /invalid cert_days/);
  assert.ok(!JSON.stringify(call.body.devices).includes('private'), 'imports never carry private key material');
});

test('minted PKI codes are repopulated after a render', async () => {
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Root', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/pki/cas/ca-a/devices': [{ id: 'dev-a', name: 'sensor-a' }, { id: 'dev-b', name: 'sensor-b' }],
    '/api/pki/cas/ca-a/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
    '/api/pki/cas/ca-a/hook': { url: '' },
    '/api/pki/cas/ca-a/attestation': { issuer: '', algorithm: 'ES256', required: false },
  } };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  await ui.invoke('selectAllPki()');
  await ui.click(ui.el('pki-mint-selected'));
  const minted = ui.el('pki-codes-out').textContent;
  assert.match(minted, /sensor-a: test-code/);
  await ui.invoke('renderPki()');
  assert.equal(ui.el('pki-codes-out').textContent, minted, 'the issued codes stay visible after a full render');
  assert.equal(ui.el('pki-download-codes').disabled, false, 'a render keeps the download control usable');
});

test('device CSV download checks the response status', async () => {
  const ui = await consoleUI();
  ui.run("fetch=async()=>({ok:false,status:403,text:async()=>JSON.stringify({error:'pki:read denied'})})");
  await ui.invoke('downloadDevices()');
  assert.match(ui.el('toasts').textContent, /pki:read denied/, 'a rejected export must report the server error');
});

test('hook and attestation settings fail closed when their reads fail', async () => {
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Root', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/pki/cas/ca-a/devices': [{ id: 'dev-a', name: 'sensor-a' }],
    '/api/pki/cas/ca-a/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
  }, fetchOverride: call => {
    if (call.method === 'GET' && call.url === '/api/pki/cas/ca-a/hook') throw new Error('hook read denied');
    if (call.method === 'GET' && call.url === '/api/pki/cas/ca-a/attestation') throw new Error('attestation read denied');
  } };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  for (const id of ['hook-url', 'hook-secret', 'hook-save', 'att-issuer', 'att-alg', 'att-required', 'att-key', 'att-save'])
    assert.ok(ui.el(id).disabled, id + ' must stay disabled after a failed read');
  assert.equal(ui.run('PKI_HOOK'), null);
  assert.equal(ui.run('PKI_ATT'), null);
  await ui.invoke('saveHook()');
  await ui.invoke('saveAttestation()');
  assert.deepEqual(ui.writes(), [], 'a failed read must never let a save overwrite the stored policy');
  assert.match(ui.el('toasts').textContent, /hook read denied/);
  assert.match(ui.el('toasts').textContent, /attestation read denied/);
});

test('policy forms enable only after their reads and attestation keeps the stored mode', async () => {
  let resolveHook, resolveAtt;
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Root', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/pki/cas/ca-a/devices': [],
    '/api/pki/cas/ca-a/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
  }, fetchOverride: call => {
    if (call.method === 'GET' && call.url === '/api/pki/cas/ca-a/hook')
      return new Promise(resolve => { resolveHook = () => resolve({ url: 'https://inventory.example/pki/enroll' }); });
    if (call.method === 'GET' && call.url === '/api/pki/cas/ca-a/attestation')
      return new Promise(resolve => { resolveAtt = () => resolve({ mode: 'tpm2', issuer: 'att-svc', algorithm: 'ES256', required: true }); });
    if (call.method === 'PUT' && call.url === '/api/pki/cas/ca-a/attestation')
      return { mode: call.body.mode, issuer: call.body.issuer, algorithm: call.body.algorithm, required: call.body.required };
  } };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  assert.ok(ui.el('hook-save').disabled);
  assert.ok(ui.el('att-save').disabled);
  await ui.invoke('saveHook()');
  await ui.invoke('saveAttestation()');
  assert.deepEqual(ui.writes(), [], 'no save may run before the reads complete');
  resolveHook(); await ui.settle();
  assert.equal(ui.el('hook-url').value, 'https://inventory.example/pki/enroll');
  assert.equal(ui.el('hook-save').disabled, false);
  assert.ok(ui.el('att-save').disabled, 'attestation stays locked until its own read returns');
  resolveAtt(); await ui.settle();
  assert.equal(ui.el('att-required').checked, true);
  assert.equal(ui.run('PKI_ATT.mode'), 'tpm2');
  await ui.click(ui.el('att-save'));
  const put = ui.calls.find(c => c.method === 'PUT' && c.url === '/api/pki/cas/ca-a/attestation');
  assert.ok(put, 'the loaded form saves');
  assert.equal(put.body.mode, 'tpm2', 'an ordinary save preserves the stored tpm2 mode');
  assert.equal(put.body.required, true);
});

test('switching CA discards the previous policy form before the new settings load', async () => {
  let holdB = false, resolveBHook;
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Root A', kind: 'root', certificate: 'A-CERT' }, { id: 'ca-b', name: 'Root B', kind: 'root', certificate: 'B-CERT' }],
    '/api/pki/cas/ca-a/devices': [{ id: 'dev-a', name: 'sensor-a' }],
    '/api/pki/cas/ca-b/devices': [],
    '/api/pki/cas/ca-a/groups': [], '/api/pki/cas/ca-b/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
    '/api/pki/cas/ca-a/hook': { url: 'https://a.example/hook' },
    '/api/pki/cas/ca-a/attestation': { mode: 'jwt', issuer: 'a-svc', algorithm: 'ES256', required: true },
    '/api/pki/cas/ca-b/attestation': { mode: 'jwt', issuer: '', algorithm: 'ES256', required: false },
  }, fetchOverride: call => {
    if (holdB && call.method === 'GET' && call.url === '/api/pki/cas/ca-b/hook')
      return new Promise(resolve => { resolveBHook = () => resolve({ url: 'https://b.example/hook' }); });
  } };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  await ui.settle();
  const oldSave = ui.el('att-save');
  assert.equal(oldSave.disabled, false);
  assert.equal(ui.run('PKI_ATT.ca'), 'ca-a');
  holdB = true;
  ui.run("switchPkiCA('ca-b')");
  assert.equal(ui.document.getElementById('att-save'), null, 'the old form is replaced immediately');
  assert.equal(ui.run('PKI_HOOK'), null);
  assert.equal(ui.run('PKI_ATT'), null);
  assert.equal(ui.run('PKI_CA'), 'ca-b');
  await ui.click(oldSave);
  await ui.invoke('saveHook()');
  assert.deepEqual(ui.writes(), [], 'detached handlers must not save under the new CA');
  assert.ok(ui.el('att-save').disabled, 'the new attestation form waits for its own read');
  assert.ok(ui.el('hook-save').disabled, 'the new hook form waits for its own read');
  resolveBHook(); await ui.settle();
  assert.equal(ui.el('hook-url').value, 'https://b.example/hook');
  assert.equal(ui.el('hook-save').disabled, false);
  assert.equal(ui.el('att-required').checked, false);
  assert.equal(ui.run('PKI_ATT.mode'), 'jwt');
  assert.deepEqual(ui.writes(), [], 'loading the new policy must not write anything');
});

test('switching workspace clears PKI selections, codes and cached policy for the same CA id', async () => {
  const opts = { pki: true, responses: {
    '/api/orgs/org-a/pki/cas': [{ id: 'ca-a', name: 'Shared', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/orgs/org-b/pki/cas': [{ id: 'ca-a', name: 'Shared', kind: 'root', certificate: 'PUBLIC TEST CERT' }],
    '/api/pki/cas/ca-a/devices': [{ id: 'dev-a', name: 'sensor-a' }],
    '/api/pki/cas/ca-a/groups': [],
    '/api/orgs/org-a/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
    '/api/orgs/org-b/pki/expiring?days=30': { counts: { 7: 0, 14: 0, 30: 0 } },
    '/api/pki/cas/ca-a/hook': { url: '' },
    '/api/pki/cas/ca-a/attestation': { mode: 'jwt', issuer: '', algorithm: 'ES256', required: false },
    '/api/orgs/org-b/settings': {}, '/api/orgs/org-b/saml': { configured: false }, '/api/orgs/org-b/ssh/cas': [],
  } };
  const ui = await consoleUI([saved], [], opts);
  await ui.invoke('renderSettings()');
  await ui.invoke('selectAllPki()');
  await ui.click(ui.el('pki-mint-selected'));
  assert.match(ui.el('pki-codes-out').textContent, /test-code/);
  assert.equal(ui.run('PKI_SELECTED.size'), 1);
  await ui.invoke("switchOrg('org-b')");
  assert.equal(ui.run('PKI_CODE_RESULTS.length'), 0);
  assert.equal(ui.run('PKI_SELECTED.size'), 0);
  assert.equal(ui.run('PKI_SELECTION_CA'), '');
  assert.equal(ui.run('PKI_HOOK'), null);
  assert.equal(ui.run('PKI_ATT'), null);
  await ui.invoke('renderSettings()');
  assert.equal(ui.el('pki-codes-out').textContent, '');
  assert.equal(ui.el('pki-selection-count').textContent, '0 selected');
  assert.equal(ui.el('pki-download-codes').disabled, true);
});

test('the theme resolves from the system by default and the toggle persists an override', async () => {
  const ui = await consoleUI();
  const html = ui.document.documentElement;
  assert.equal(html.getAttribute('data-theme-pref'), 'system', 'with nothing stored the console follows the system');
  assert.equal(html.getAttribute('data-theme'), 'light', 'the shim exposes no dark system preference');
  const toggle = ui.document.querySelector('.topbar [data-themetoggle]');
  assert.ok(toggle, 'the topbar exposes a theme toggle');
  assert.ok(ui.document.querySelector('.authprefs [data-themetoggle]'), 'the auth card exposes one too');
  await ui.click(toggle);
  assert.equal(ui.store['ow_theme'], 'light', 'cycling from system selects light');
  assert.equal(html.getAttribute('data-theme'), 'light');
  await ui.click(ui.document.querySelector('.topbar [data-themetoggle]'));
  assert.equal(ui.store['ow_theme'], 'dark', 'a second click selects dark');
  assert.equal(html.getAttribute('data-theme'), 'dark');
  await ui.click(ui.document.querySelector('.topbar [data-themetoggle]'));
  assert.equal(ui.store['ow_theme'], 'system', 'a third click returns to following the system');
  assert.equal(html.getAttribute('data-theme'), 'light', 'system resolves through the (light) shim preference');
});

test('OS theme changes follow the current choice, not the initial choice', async () => {
  for (const initial of ['system', 'dark']) {
    const ui = await consoleUI([saved], [], { store: { ow_theme: initial } });
    const html = ui.document.documentElement;
    await ui.invoke("setTheme('light')");
    ui.systemDark(true);
    assert.equal(html.dataset.theme, 'light');
    await ui.invoke("setTheme('dark')");
    ui.systemDark(false);
    assert.equal(html.dataset.theme, 'dark');
    await ui.invoke("setTheme('system')");
    ui.systemDark(true);
    assert.equal(html.dataset.theme, 'dark');
    ui.systemDark(false);
    assert.equal(html.dataset.theme, 'light');
  }
});

test('light and dark are fully tokenized and the i18n runtime is wired', () => {
  for (const token of ['--bg', '--panel', '--text', '--acc', '--toast-bg', '--sh-auth']) {
    assert.match(source, new RegExp(`:root{[^}]*${token}:`), `the light theme must define ${token}`);
    assert.match(source, new RegExp(`:root\\[data-theme=dark\\]{[^}]*${token}:`), `the dark theme must define ${token}`);
  }
  assert.match(source, /color-scheme:light/, 'the light root declares color-scheme');
  assert.match(source, /:root\[data-theme=dark\]{color-scheme:dark/, 'the dark root declares color-scheme');
  const appSource = fs.readFileSync(path.join(__dirname, '../src/app.rs'), 'utf8');
  assert.match(appSource, /route\("\/i18n\.js"/, 'the server must serve /i18n.js');
  assert.match(source, /<script src="\/i18n\.js"/, 'the console must load the i18n runtime before the inline script');
  assert.match(source, /data-themetoggle/, 'theme toggles must exist in the chrome');
});

test('every language dictionary carries the same keys and every key exists in the console', () => {
  const ctx = vm.createContext({ localStorage: { getItem: () => '', setItem() {}, removeItem() {} } });
  vm.runInContext(i18nSource, ctx, { filename: 'i18n.js' });
  const langs = vm.runInContext('Object.keys(OW_LANGS)', ctx);
  assert.ok(langs.length >= 9, 'at least nine locales ship, English included');
  const keys = vm.runInContext(`Object.keys(OW_I18N['zh-TW']).sort()`, ctx);
  assert.ok(keys.length > 200, 'the dictionaries are substantive, not a stub');
  for (const lang of langs.filter(l => l !== 'en')) {
    assert.deepEqual(vm.runInContext(`Object.keys(OW_I18N[${JSON.stringify(lang)}]).sort()`, ctx), keys,
      `${lang} must cover the same strings as the other languages`);
  }
  const flat = source.replace(/\\'/g, "'").replace(/&amp;/g, '&');
  const composed = ['Request approved', 'Request rejected', 'Signups enabled', 'Signups disabled',
    'Theme: system', 'Theme: light', 'Theme: dark'];
  for (const key of keys) {
    if (composed.includes(key)) continue;
    assert.ok(flat.includes(key), `dictionary key missing from the console source: ${key}`);
  }
});

test('language changes do not translate app names matching interface labels', async () => {
  const names = ['Settings', '設定'];
  const ui = await consoleUI([saved], [], { responses: {
    '/api/orgs/org-a/apps': names.map((name, i) => ({ id: i ? 'app-b' : 'app-a', name })),
  } });
  for (const lang of ['ja', 'fr', 'en']) {
    await ui.invoke('renderApps()');
    await ui.invoke(`owSetLang(${JSON.stringify(lang)})`);
    assert.deepEqual(ui.el('view').querySelectorAll('.appcard h3').map(el => el.textContent), names,
      `app cards must preserve names in ${lang}`);
    for (const [i, name] of names.entries()) {
      await ui.invoke(`openApp('${i ? 'app-b' : 'app-a'}')`);
      await ui.invoke('owApply()');
      assert.equal(ui.el('pagetitle').textContent, name, `the app title must preserve its name in ${lang}`);
    }
  }
});

for (const [label, initial, next] of [['Settings', 'en', 'ja'], ['設定', 'ja', 'en']]) {
  test(`language changes preserve audit detail ${JSON.stringify(label)} from ${initial} to ${next}`, async () => {
    const ui = await consoleUI([saved], [], { store: { ow_lang: initial }, responses: {
      '/api/orgs/org-a/audit': [{ action: 'fixture.event', actor: 'fixture-user', detail: label }],
    } });
    await ui.invoke('renderAudit()');
    assert.equal(ui.el('view').querySelector('tbody tr').querySelectorAll('td')[3].textContent, label);
    for (const lang of [next, 'fr', initial]) {
      await ui.invoke(`owSetLang(${JSON.stringify(lang)})`);
      assert.equal(ui.el('view').querySelector('tbody tr').querySelectorAll('td')[3].textContent, label,
        `audit data must remain verbatim after switching to ${lang}`);
      assert.equal(ui.el('pagetitle').textContent,
        { en: 'Audit log', ja: '監査ログ', fr: "Journal d'audit" }[lang], 'the surrounding UI still translates');
    }
  });
}

test('language changes preserve label-like access request reasons and translate their controls', async () => {
  const reasons = ['Settings', '設定'];
  const ui = await consoleUI([saved], [], { responses: {
    '/api/orgs/org-a/teams': [], '/api/orgs/org-a/roles': [], '/api/orgs/org-a/members': [],
    '/api/envs/env-a/proposals': [],
    '/api/envs/env-a/access-requests': reasons.map((reason, i) => ({ id: 'request-' + i, reason, status: 'pending' })),
  } });
  await ui.invoke('renderAccess()');
  for (const [lang, approve] of [['ja', '承認'], ['en', 'Approve']]) {
    await ui.invoke(`owSetLang(${JSON.stringify(lang)})`);
    const cards = ui.el('view').querySelectorAll('.card');
    const requests = cards.find(card => card.querySelector('button[onclick="requestAccess()"]'));
    assert.ok(requests, 'the access request card must render');
    assert.deepEqual(requests.querySelectorAll('.row .small').map(el => el.textContent),
      reasons.map(reason => reason + ' · pending'), 'request reasons must remain verbatim');
    assert.equal(requests.querySelector('button').textContent, approve, 'request controls still translate');
  }
});

test('the full removed-key-grant security explanation translates and returns to English', async () => {
  const ui = await consoleUI();
  ui.run("ENV.mode='e2e'; E2E_DATA[ENV.id]=[]; E2E_META[ENV.id]={rekey_required:true}");
  await ui.invoke('renderE2eEnv()');
  const explanation = ui.el('view').querySelector('.card p');
  assert.ok(explanation, 'removing a grant must expose the rotation explanation');
  const english = explanation.textContent;
  assert.match(english, /Rotation cannot take back ciphertext someone already copied\./);
  await ui.invoke("owSetLang('ja')");
  assert.equal(explanation.textContent,
    'メンバーの鍵グラントが削除されましたが、保存された暗号文はまだ古い環境鍵で暗号化されています。鍵をローテーションして、すべてのシークレットを新しい鍵で再暗号化し、現在のメンバーへ包鍵してください。ローテーションでも、すでにコピーされた暗号文は取り戻せません。');
  await ui.invoke("owSetLang('en')");
  assert.equal(explanation.textContent, english, 'switching back restores the full security explanation');
});

test('language reset clears the override and detects the current browser language', async () => {
  const ui = await consoleUI([saved], [], { languages: ['ja'], store: { ow_lang: 'fr' } });
  assert.equal(ui.document.documentElement.getAttribute('lang'), 'fr');
  assert.ok(ui.document.querySelector('select[data-langsel]').querySelector('option[value="system"]'));
  await ui.invoke("owSetLang('en')");
  assert.equal(ui.store.ow_lang, 'en');
  await ui.invoke("owSetLang('system')");
  assert.equal(ui.store.ow_lang, undefined);
  assert.equal(ui.document.documentElement.getAttribute('lang'), 'ja');
  for (const select of ui.document.querySelectorAll('select[data-langsel]')) assert.equal(select.value, 'system');
});

test('language follows the browser, translates the chrome, and the override persists', async () => {
  const ui = await consoleUI([saved], [], { languages: ['zh-TW', 'en'] });
  const html = ui.document.documentElement;
  assert.equal(html.getAttribute('lang'), 'zh', 'the document language tracks the browser');
  assert.equal(ui.store['ow_lang'], undefined, 'a detected language writes no override');
  assert.equal(ui.el('authtitle').textContent, '歡迎回來', 'the static auth screen is translated at boot');
  await ui.invoke('renderApps(); owApply()');
  assert.ok(ui.el('view').innerHTML.includes('個應用程式'), 'rendered app counts are translated');
  await ui.run(`owSetLang('ja')`);
  assert.equal(ui.store['ow_lang'], 'ja', 'the override persists');
  assert.equal(html.getAttribute('lang'), 'ja');
  assert.equal(ui.el('authtitle').textContent, 'おかえりなさい', 'switching languages re-translates the chrome');
  await ui.run(`owSetLang('en')`);
  assert.equal(ui.el('authtitle').textContent, 'Welcome back', 'returning to English restores the source strings');
});

test('settings lists browser sessions and revokes only the chosen one', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    '/api/me/sessions': [
      { id: 'session-current', created_at: 1700000000, current: true },
      { id: 'session-other', created_at: 1699990000, current: false },
    ],
  } });
  ui.run("ORG='org-a'");
  await ui.invoke('renderSettings()');
  await ui.invoke('loadSessions()');
  const rows = ui.el('session-list').querySelectorAll('tbody tr');
  assert.equal(rows.length, 2, 'one row per browser session');
  assert.match(rows[0].textContent, /this session/, 'the current session is marked');
  ui.confirm = true;
  await ui.click(ui.button(rows[1], /^Revoke$/));
  assert.deepEqual(ui.writes().map(c => [c.method, c.url]), [['DELETE', '/api/me/sessions/session-other']],
    'revoking one session targets that id only');
});

test('the logs screen separates audit, sync activity and delivery attempts', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    '/api/orgs/org-a/audit': [
      { action: 'secret.read', detail: '1 key', actor: 'fixture-user', created_at: 1700000000 },
      { action: 'integration.sync_failed', detail: 'int-1: provider rejected the token', actor: 'fixture-user', created_at: 1700000001 },
      { action: 'rotation.run', detail: 'STRIPE_KEY', actor: 'fixture-user', created_at: 1700000002 },
    ],
    '/api/orgs/org-a/log-streams/deliveries': [
      { id: 'd1', stream_name: 'SIEM', stream_url: 'https://siem.example/ingest', event: 'secret.read', status: 'failed', attempts: 3, created_at: 1700000003 },
    ],
  } });
  ui.run("ORG='org-a'");
  await ui.invoke('renderAudit()');
  assert.match(ui.el('auditrows').textContent, /secret\.read/, 'the audit tab lists workspace events');
  await ui.invoke("setLogTab('sync')");
  const sync = ui.el('auditrows').textContent;
  assert.match(sync, /integration\.sync_failed/);
  assert.match(sync, /rotation\.run/);
  assert.doesNotMatch(sync, /secret\.read/, 'sync activity hides unrelated events');
  await ui.invoke("setLogTab('delivery')");
  const deliveries = ui.el('auditrows').textContent;
  assert.match(deliveries, /SIEM/, 'delivery rows name the target stream');
  assert.match(deliveries, /failed/);
  assert.match(deliveries, /3/);
  assert.equal(ui.el('auditcount').textContent, '1 attempts shown');
});

test('the self-hosted plan shows its plan card and locks enterprise settings', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    '/api/auth/providers': { ldap: true },
    '/api/orgs/org-a/ldap': {},
  } });
  ui.run("ORG='org-a'");
  await ui.invoke('renderSettings()');
  const view = ui.el('view');
  assert.match(view.textContent, /Self-hosted/, 'the plan card names the self-hosted plan');
  assert.match(view.textContent, /All core features are enabled without a license/);
  assert.match(view.textContent, /SAML SSO/, 'the locked SAML card is still discoverable');
  assert.match(view.textContent, /Enterprise/, 'the locked cards carry the enterprise label');
  assert.equal(ui.el('set-oidc-iss').disabled, true, 'workspace OIDC fields are read-only without a license');
  assert.equal(ui.button(view, /^Save SAML$/), undefined, 'no SAML save action is offered while locked');
});

test('an enterprise edition unlocks the settings forms', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    '/api/auth/providers': { ldap: true },
    '/api/orgs/org-a/ldap': {},
  } });
  ui.run("ORG='org-a'");
  ui.run("EDITION={tier:'enterprise',enterprise:true,customer:'Acme Ltd',expires_at:null,development:false,warning:null}");
  await ui.invoke('renderSettings()');
  const view = ui.el('view');
  assert.match(view.textContent, /Licensed to Acme Ltd/);
  assert.equal(ui.el('set-oidc-iss').disabled, false, 'OIDC fields are editable with a license');
  assert.ok(ui.button(view, /^Save SAML$/), 'the SAML form is available with a license');
});
// A stale digest silently blocks the console's translation script in every
// browser, so each SRI hash must match the file it names.
test('console script digests match the files they load', () => {
  const crypto = require('node:crypto');
  const files = {
    'i18n.js': path.join(__dirname, '../src/i18n.js'),
    'libsodium.js': path.join(__dirname, '../src/vendor/libsodium.js'),
    'libsodium-wrappers.js': path.join(__dirname, '../src/vendor/libsodium-wrappers.js'),
  };
  for (const [name, file] of Object.entries(files)) {
    const digest = crypto.createHash('sha384').update(fs.readFileSync(file)).digest('base64');
    assert.ok(html.includes(`<script src="/${name}" integrity="sha384-${digest}"`),
      `${name} must carry the digest of its current contents`);
  }
});
test('a member of several workspaces chooses one, and the choice survives the next visit', async () => {
  const ui = await consoleUI([saved], [], { manualBoot: true, store: { 'ow.org.fixture@example.invalid': '' } });
  await ui.invoke('enterApp()');
  assert.equal(ui.el('picker').style.display, 'grid', 'a member of two workspaces must be asked which one to open');
  assert.equal(ui.el('shell').style.display, 'none', 'the shell must not open behind the picker');
  const rows = ui.el('pickerlist').children.filter(child => typeof child !== 'string');
  assert.equal(rows.length, 2, 'both workspaces must be offered');
  assert.match(rows[0].textContent, /First org/);
  assert.match(rows[0].textContent, /3 members/, 'the picker shows how large a workspace is');
  assert.match(rows[1].textContent, /1 member\b/, 'a single-member workspace is not pluralised');
  assert.match(rows[1].textContent, /admin/, 'the picker shows the role held there');

  await ui.invoke("pickOrg('org-b')");
  assert.equal(ui.el('picker').style.display, 'none', 'picking a workspace closes the picker');
  assert.equal(ui.el('orgname').textContent, 'Second org', 'the switcher names the chosen workspace');

  // The remembered choice is what a returning browser lands in.
  await ui.invoke('enterApp()');
  assert.equal(ui.el('picker').style.display, 'none', 'a remembered workspace must not ask again');
  assert.equal(ui.el('orgname').textContent, 'Second org');
});

test('the login screen names its jurisdiction and offers another only when one exists', async () => {
  const local = await consoleUI([saved], [], { manualBoot: true, responses: {
    '/api/auth/providers': { region: 'global', regions: [], google: false, signups: 'open' },
  } });
  await local.invoke('loadProviders()');
  assert.match(local.el('regionline').textContent, /global/, 'a single deployment still states its jurisdiction');
  assert.doesNotMatch(local.el('regionline').textContent, /Change region/, 'no switch is offered when there is nowhere to go');

  const multi = await consoleUI([saved], [], { manualBoot: true, responses: {
    '/api/auth/providers': { region: 'eu', regions: [
      { label: 'global', origin: 'https://global.example.test' },
      { label: 'eu', origin: 'https://eu.example.test' },
    ] },
  } });
  await multi.invoke('loadProviders()');
  assert.match(multi.el('regionline').textContent, /eu/, 'the login screen names the jurisdiction it will authenticate against');
  assert.match(multi.el('regionline').textContent, /Change region/, 'a second jurisdiction is offered as a hand-off');
  await multi.invoke('regionPick()');
  assert.match(multi.el('modal').textContent, /GLOBAL/, 'the picker lists the jurisdictions by name');
  assert.match(multi.el('modal').textContent, /EU/, 'the picker lists the jurisdictions by name');
});

test('the workspace menu keeps workspace actions apart from account actions', async () => {
  const ui = await consoleUI();
  assert.equal(ui.el('orgbtn').getAttribute('aria-expanded'), 'false', 'the menu starts closed');
  await ui.invoke('toggleOrgMenu()');
  assert.equal(ui.el('orgbtn').getAttribute('aria-expanded'), 'true', 'the trigger reports the open state');
  const menu = ui.el('orgmenu').textContent;
  assert.match(menu, /First org/);
  assert.match(menu, /Second org/);
  assert.match(menu, /fixture@example\.invalid/, 'the account holding the session is named once');
  assert.match(menu, /Account settings/);
  assert.match(menu, /Sign out/);
  assert.ok(menu.indexOf('Second org') < menu.indexOf('Account settings'), 'workspaces come before account actions');
  const items = ui.el('orgmenu').querySelectorAll('button.orgitem');
  assert.ok(items.length >= 4, 'the menu exposes its actions as buttons');
  assert.equal(ui.document.activeElement, items[0], 'opening the menu focuses its first action');
  await ui.invoke('orgMenuKey({key: "ArrowDown", preventDefault() {}})');
  assert.equal(ui.document.activeElement, items[1], 'ArrowDown moves within the menu');
  await ui.invoke('orgMenuKey({key: "ArrowUp", preventDefault() {}})');
  assert.equal(ui.document.activeElement, items[0], 'ArrowUp moves back');
  await ui.invoke('closeOrgMenu()');
  assert.equal(ui.el('orgbtn').getAttribute('aria-expanded'), 'false');
  await ui.invoke("switchOrg('org-b')");
  assert.equal(ui.el('orgname').textContent, 'Second org', 'switching updates the trigger, not just the state');
  await ui.invoke('toggleOrgMenu()');
  assert.match(ui.el('orgmenu').textContent, /✓\s*Second org/, 'the open menu marks the selected workspace');
});

// ---------- workspace member locks ----------
test('a locked workspace shows the owner contact message without fetching workspace data', async () => {
  const ui = await consoleUI([saved], [], {
    manualBoot: true,
    responses: {
      '/api/orgs': [{ id: 'org-locked', name: 'Locked org', role: 'member', members: 1, locked: true }],
      '/api/orgs/org-locked/emergency': { locked: false },
    },
  });
  await ui.invoke('enterApp()');
  const view = ui.el('view');
  assert.match(view.textContent, /locked/i, 'the locked workspace must say it is locked');
  assert.match(view.textContent, /workspace owner/ , 'the member must be told to contact the workspace owner');
  assert.equal(ui.el('pagetitle').textContent, 'Workspace access locked');
  assert.match(ui.el('orgmenu').textContent, /locked/i, 'the workspace menu must mark the locked workspace');
  assert.ok(!ui.calls.some(c => c.url === '/api/orgs/org-locked/apps'),
    'a locked workspace must not fetch workspace data such as apps');
});

test('an owner can lock a member from the members list', async () => {
  const ui = await consoleUI([saved], [], { responses: {
    '/api/me': { id: 'owner-a', email: 'owner@example.invalid' },
    '/api/orgs/org-a/members': [{ id: 'owner-a', email: 'owner@example.invalid', role: 'owner' }, { id: 'member-a', email: 'member@example.invalid', role: 'developer' }],
    '/api/orgs/org-a/teams': [], '/api/orgs/org-a/roles': [{ name: 'developer', permissions: [] }], '/api/orgs/org-a/invites': [],
    '/api/orgs/org-a/features': { compiled: [], granted: [] },
    'POST /api/orgs/org-a/members/member-a/lock': { ok: true, locked: stable_counter = 0, locked: true },
  } });
  await ui.invoke("nav('access')");
  const lock = ui.button(ui.el('view'), /^Lock$/);
  assert.ok(lock, 'an owner must see a Lock control for a non-owner member');
  ui.confirm = true;
  beforeLock = ui.calls.length;
  await ui.click(lock);
  assert.ok(ui.calls.slice(beforeLock).some(c => c.method === 'POST' && c.url === '/api/orgs/stable' && false) || ui.calls.some(c => c.method === 'POST' && c.url === '/api/orgs/org-a/members/member-a/lock'),
    'locking must POST the member lock route');
});

test('an owner can unlock a member from the members list', async () => {
  const corruption = 0; // guard against accidental fixture drift
  const ui = await consoleUI([saint] = [saved], [], { responses: {
    '/api/me': { id: 'owner-a', email: 'owner@example.invalid' },
    '/api uninitialized': null,
    '/api/orgs/org-a/members': [{ id: 'member-a', email: 'injected@example.invalid', role: 'developer', locked: true }],
    '/api/orgs/org-a/teams': [], '/api/orgs/org-a-roles': [], '/api/orgs/org-a/roles': [{ name: 'developer', '/api/orgs/org-a/invites': [], }],
    '/api/orgs/org-a/features': { compiled: [], granted: [] },
    'POST /api/orgs/malformed': { ok: true },
    'POST /api/orgs/org-a/members/member-a/unlock': { ok: true, locked: false },
  } });
  await ui.in
