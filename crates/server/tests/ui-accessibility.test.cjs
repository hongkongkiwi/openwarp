'use strict';

// Run with node --test crates/server/tests/ui-accessibility.test.cjs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
const html = source.match(/r##"([\s\S]*)"##;/)?.[1];
assert.ok(html, 'embedded console HTML must be extractable');
const script = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
  .filter(([, attrs]) => !/\bsrc\s*=/.test(attrs)).map(([, , body]) => body).join('\n');
const decode = value => String(value).replace(/&(amp|lt|gt|quot|apos|#39);/g,
  (_, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'" }[name]));

// Only DOM operations needed by these rendered-markup and feedback checks are modeled.
class Element {
  constructor(tag, document, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.ownerDocument = document;
    this.attributes = { ...attrs };
    this.children = [];
    this.style = {};
    this.dataset = new Proxy({}, {
      get: (_, key) => this.getAttribute('data-' + key),
      set: (_, key, value) => { this.setAttribute('data-' + key, value); return true; },
    });
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: name => { if (!this.classList.contains(name)) this.className += ' ' + name; },
      remove: name => { this.className = this.className.split(/\s+/).filter(x => x !== name).join(' '); },
      toggle: (name, force) => this.classList[force ? 'add' : 'remove'](name),
    };
  }
  get id() { return this.getAttribute('id') || ''; }
  set id(value) { this.setAttribute('id', value); }
  get className() { return this.getAttribute('class') || ''; }
  set className(value) { this.setAttribute('class', value); }
  get value() { return this._value ?? this.getAttribute('value') ?? ''; }
  set value(value) { this._value = String(value); }
  get textContent() { return this.children.map(c => typeof c === 'string' ? c : c.textContent).join(''); }
  set textContent(value) { this.children = [String(value)]; }
  get innerHTML() { return this.children.map(c => typeof c === 'string' ? c : c.outerHTML).join(''); }
  set innerHTML(value) { this.children = []; parse(String(value), this); }
  get outerHTML() {
    return `<${this.tagName.toLowerCase()}${Object.entries(this.attributes).map(([k, v]) => ` ${k}="${v}"`).join('')}>${this.innerHTML}</${this.tagName.toLowerCase()}>`;
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  appendChild(child) { this.children.push(child); child.parentElement = this; return child; }
  remove() { this.parentElement.children = this.parentElement.children.filter(c => c !== this); }
  addEventListener() {}
  focus() { this.ownerDocument.activeElement = this; }
  matches(selector) {
    const tag = selector.match(/^[\w-]+/);
    if (tag && this.tagName !== tag[0].toUpperCase()) return false;
    for (const [, id] of selector.matchAll(/#([\w-]+)/g)) if (this.id !== id) return false;
    for (const [, name] of selector.matchAll(/\.([\w-]+)/g)) if (!this.classList.contains(name)) return false;
    for (const [, name, , value] of selector.matchAll(/\[([\w-]+)(?:=(["'])(.*?)\2)?\]/g)) {
      if (this.getAttribute(name) === null || (value !== undefined && this.getAttribute(name) !== value)) return false;
    }
    return true;
  }
  querySelectorAll(selector) {
    const found = [];
    const walk = root => {
      for (const child of root.children) if (typeof child !== 'string') {
        if (selector.split(',').some(s => child.matches(s.trim()))) found.push(child);
        walk(child);
      }
    };
    walk(this);
    return found;
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
    assert.ok(tag, 'unsupported HTML token: ' + token);
    const attrs = {};
    for (const [, name, , quoted, bare] of rest.matchAll(/([^\s=/>]+)(?:\s*=\s*(?:(["'])([\s\S]*?)\2|([^\s>]+)))?/g)) attrs[name] = decode(quoted ?? bare ?? '');
    const el = new Element(tag, root.ownerDocument, attrs);
    stack.at(-1).appendChild(el);
    if (!/^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/i.test(tag)) stack.push(el);
  }
}

async function consoleUI({ clipboardFails = false } = {}) {
  const document = new Element('document', null);
  document.ownerDocument = document;
  document.getElementById = id => document.querySelector('#' + id);
  document.createElement = tag => new Element(tag, document);
  parse(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<style>[\s\S]*?<\/style>/gi, ''), document);
  document.body = document.querySelector('body');
  document.activeElement = document.body;
  const replies = new Map([
    ['/api/auth/providers', { signups: 'open' }],
    ['/api/orgs/org-a/apps', [{ id: 'app-a', name: 'Billing' }]],
    ['/api/apps/app-a/envs', []],
    ['/api/search?q=bi', { results: [{ key: 'BILLING_KEY', app: 'Billing', env: 'Development' }] }],
    ['/api/orgs/org-a/audit', []],
  ]);
  const failures = new Set(), calls = [], writes = [], unexpected = [];
  const context = vm.createContext({
    document, console, URL, TextDecoder, TextEncoder,
    localStorage: { getItem: () => '', setItem() {}, removeItem() {} },
    location: { hash: '', pathname: '/', origin: 'http://console.invalid' },
    history: { replaceState() {} },
    setTimeout() {}, clearTimeout() {}, requestAnimationFrame: fn => fn(),
    navigator: { clipboard: { writeText(value) {
      writes.push(value);
      const result = clipboardFails ? Promise.reject(new Error('Clipboard denied')) : Promise.resolve();
      // Observe the rejection here so the regression reports false success, not an unhandled rejection.
      result.catch(() => {});
      return result;
    } } },
    fetch: async (url, options) => {
      calls.push(url);
      if (!replies.has(url)) { unexpected.push(url); throw new Error('Missing fixture: ' + url); }
      return { ok: !failures.has(url), status: failures.has(url) ? 503 : 200,
        text: async () => JSON.stringify(failures.has(url) ? { error: 'Service unavailable' } : replies.get(url)) };
    },
  });
  const run = code => vm.runInContext(code, context, { timeout: 1000 });
  run(script);
  for (let i = 0; i < 20; i++) await Promise.resolve();
  run("ORG='org-a'");
  return {
    document, replies, failures, calls, writes, run,
    el: id => document.getElementById(id),
    async invoke(code) {
      await run(code);
      for (let i = 0; i < 20; i++) await Promise.resolve();
      assert.deepEqual(unexpected, [], 'every API read must have a fixture');
    },
  };
}

function accessibleName(el, document) {
  return el.getAttribute('aria-label') || (el.getAttribute('aria-labelledby') || '').split(/\s+/)
    .filter(Boolean).map(id => document.getElementById(id)?.textContent || '').join(' ');
}

function visibleText(el) {
  if (el.style.display === 'none' || el.getAttribute('hidden') !== null) return '';
  return el.children.map(c => typeof c === 'string' ? c : visibleText(c)).join('');
}

function nativeControl(el) {
  return el.tagName === 'BUTTON' || (el.tagName === 'A' && !!el.getAttribute('href'));
}

test('default modal names follow the heading without retaining an earlier explicit name', async () => {
  const ui = await consoleUI();
  await ui.invoke("forgotPrompt()");
  assert.match(accessibleName(ui.el('modal'), ui.document), /reset password/i);
  await ui.invoke('closeModal(); newApp()');
  assert.equal(ui.el('modal').getAttribute('role'), 'dialog');
  assert.match(accessibleName(ui.el('modal'), ui.document), /new app/i,
    'a modal opened without an explicit label must derive its accessible name from its heading');
});

for (const clipboardFails of [true, false]) {
  test(`clipboard ${clipboardFails ? 'rejection never reports success' : 'success still reports the copied value'}`, async () => {
    const ui = await consoleUI({ clipboardFails });
    ui.replies.set('/api/apps/app-a/envs', [{ id: 'env-a', name: 'Development' }]);
    ui.replies.set('/api/envs/env-a/secrets', { secrets: [{ id: 'secret-a', key: 'KEY', value: 'fixture-value', type: 'secret' }] });
    await ui.invoke("openApp('app-a')");
    const copy = ui.el('stable').querySelector('[aria-label="Copy value"]');
    assert.ok(copy, 'saved secrets retain a copy control');
    await ui.invoke(`copyVal(document.querySelector('[aria-label="Copy value"]'))`);
    assert.deepEqual(ui.writes, ['fixture-value'], 'copy must use the stored value, not its masked text');
    const feedback = ui.el('toasts').textContent;
    if (clipboardFails) assert.doesNotMatch(feedback, /copied/i, 'a rejected clipboard write must not produce a success toast');
    else assert.match(feedback, /copied/i);
  });
}

test('app filtering announces no matches and clearing restores the existing app', async () => {
  const ui = await consoleUI();
  await ui.invoke('renderApps();');
  await ui.invoke("filterApps('BILL')");
  assert.match(visibleText(ui.el('view')), /Billing/, 'app matching remains case-insensitive');
  await ui.invoke("filterApps('not-present')");
  assert.match(visibleText(ui.el('view')), /no .*match|no results/i, 'a zero-result app filter must explain the blank grid');
  assert.doesNotMatch(visibleText(ui.el('view')), /no apps yet/i, 'filtered apps are not an empty organization');
  await ui.invoke("filterApps('')");
  assert.match(visibleText(ui.el('view')), /Billing/);
  assert.doesNotMatch(visibleText(ui.el('view')), /no .*match|no results/i);
});

test('failed audit reads are visibly different from a successful empty audit log', async () => {
  const ui = await consoleUI();
  await ui.invoke('renderAudit()');
  assert.match(ui.el('view').textContent, /no events yet/i, 'a successful empty response retains its empty state');
  ui.failures.add('/api/orgs/org-a/audit');
  await ui.invoke('renderAudit()');
  assert.equal(ui.calls.filter(url => url.endsWith('/audit')).length, 2);
  assert.doesNotMatch(ui.el('view').textContent, /no events yet/i, 'a failed read must not claim that there are no audit events');
  assert.match(ui.el('view').textContent + ui.el('toasts').textContent,
    /unavailable|failed|error|unable|could not|couldn't/i, 'read failure must produce visible feedback');
});

test('app cards, search opener and search results use native keyboard controls', async () => {
  const ui = await consoleUI();
  await ui.invoke('renderApps()');
  ui.el('paletteinput').value = 'bi';
  await ui.invoke('paletteSearch()');
  const app = ui.el('appgrid').querySelector('.appcard');
  const opener = ui.document.querySelector('.searchbox');
  const result = ui.el('paletteresults').querySelector('.pitem');
  assert.ok(app && opener && result, 'the fixture must render all three controls');
  assert.deepEqual([app, opener, result].map(nativeControl), [true, true, true],
    'app navigation, search opening and result activation must use buttons or links with href');
});

test('mobile markup retains navigation or exposes a native navigation disclosure below 820px', () => {
  const document = new Element('document', null);
  document.ownerDocument = document;
  parse(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<style>[\s\S]*?<\/style>/gi, ''), document);
  const css = html.match(/<style>([\s\S]*?)<\/style>/i)[1];
  const mobile = css.match(/@media\s*\(\s*max-width\s*:\s*820px\s*\)\s*\{([\s\S]*)/)?.[1] || '';
  const hidesAside = /(?:^|\})\s*aside\s*\{[^}]*display\s*:\s*none\b/.test(mobile);
  const aside = document.querySelector('aside');
  const outside = document.querySelectorAll('button,a').filter(el => !el.closest('aside'));
  const disclosure = outside.some(el => nativeControl(el) && aside.id &&
    (el.getAttribute('aria-controls') || '').split(/\s+/).includes(aside.id));
  const destinations = aside.querySelectorAll('[data-nav]').map(el => el.getAttribute('data-nav'));
  const alternative = destinations.length > 0 && destinations.every(dest => outside.some(el =>
    nativeControl(el) && el.getAttribute('data-nav') === dest));
  assert.ok(!hidesAside || disclosure || alternative,
    'the mobile rule hides the sole navigation without a native disclosure or alternate navigation controls');
});
