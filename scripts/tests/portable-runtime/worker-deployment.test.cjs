'use strict';

// Run with node --test scripts/tests/portable-runtime/worker-deployment.test.cjs.
// This deployment gate proves the Wrangler configuration describes a Worker
// whose application storage is SQLite inside a Durable Object, and that the
// declared entrypoint exists. It does not execute wasm, does not prove the
// shared handlers are the ones running, and does not prove Durable Object SQL
// behaviour; scripts/worker-smoke.sh covers the runtime path against workerd.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');

function configs(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (['.git', 'target', 'node_modules', '.wrangler', 'build'].includes(entry.name)) return [];
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) return configs(filename);
    return entry.isFile() && /^wrangler\.(toml|json|jsonc)$/.test(entry.name) ? [filename] : [];
  });
}

function stripJsonComments(source) {
  let result = '';
  let quoted = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (quoted) {
      result += ch;
      if (ch === '\\') result += source[++i] || '';
      else if (ch === '"') quoted = false;
    } else if (ch === '"') {
      quoted = true;
      result += ch;
    } else if (ch === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') i++;
      result += '\n';
    } else if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i++;
      i++;
      result += ' ';
    } else result += ch;
  }
  // JSONC permits trailing commas. Do not alter commas inside JSON strings.
  return result.replace(/"(?:\\.|[^"\\])*"|,(\s*[}\]])/g, (match, closing) => closing || match);
}

// Minimal reader for the Wrangler TOML shapes this repository uses: top-level
// scalars plus arrays of tables. Comments and blank lines are stripped first.
function parseToml(source) {
  const text = source.replace(/^\s*#.*$/gm, '');
  const main = text.match(/^\s*main\s*=\s*["']([^"']+)["']/m)?.[1];
  const compatibility = text.match(/^\s*compatibility_date\s*=\s*["']([^"']+)["']/m)?.[1];
  const sections = [];
  let current = { name: '', body: '' };
  for (const line of text.split('\n')) {
    const header = line.match(/^\s*\[\[?([^\]]+)\]\]?\s*$/);
    if (header) { sections.push(current); current = { name: header[1].trim(), body: '' }; }
    else current.body += line + '\n';
  }
  sections.push(current);
  const str = (body, key) => body.match(new RegExp(`^\\s*${key}\\s*=\\s*["']([^"']*)["']`, 'm'))?.[1];
  const list = (body, key) => {
    const raw = body.match(new RegExp(`^\\s*${key}\\s*=\\s*\\[([^\\]]*)\\]`, 'm'))?.[1];
    return raw ? [...raw.matchAll(/["']([^"']*)["']/g)].map(m => m[1]) : [];
  };
  return {
    main,
    compatibility,
    doBindings: sections.filter(s => s.name === 'durable_objects.bindings')
      .map(s => ({ name: str(s.body, 'name'), class_name: str(s.body, 'class_name') })),
    // Legacy service-worker syntax keeps the class on the top-level section.
    migrations: sections.filter(s => s.name === 'migrations')
      .map(s => ({ tag: str(s.body, 'tag'), new_sqlite_classes: list(s.body, 'new_sqlite_classes') })),
    d1Bindings: sections.filter(s => s.name === 'd1_databases'),
    declaredClasses: list(text.match(/\nclass_name\s*=\s*["'][^"']*["']/g) ? text : '', 'class_name'),
  };
}

function readDeployment(filename) {
  const source = fs.readFileSync(filename, 'utf8');
  if (filename.endsWith('.toml')) return parseToml(source);
  const config = JSON.parse(stripJsonComments(source));
  const environments = [config, ...Object.values(config.env || {})];
  return {
    main: config.main,
    compatibility: config.compatibility_date,
    doBindings: environments.flatMap(env => env.durable_objects?.bindings || [])
      .map(binding => ({ name: binding.name, class_name: binding.class_name })),
    migrations: environments.flatMap(env => env.migrations || [])
      .map(migration => ({ tag: migration.tag, new_sqlite_classes: migration.new_sqlite_classes || [] })),
    d1Bindings: environments.flatMap(env => env.d1_databases || []),
  };
}

function sqliteBackedClasses(deployment) {
  const declared = new Set(deployment.migrations.flatMap(m => m.new_sqlite_classes).filter(Boolean));
  return deployment.doBindings.filter(b => b.class_name && declared.has(b.class_name));
}

test('parser self-test: SQLite Durable Object configs pass, KV-only configs fail', () => {
  const valid = parseToml(`
name = "openwarp"
main = "build/worker/shim.mjs"
compatibility_date = "2026-10-01"

[[durable_objects.bindings]]
name = "APP"
class_name = "OpenWarp"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["OpenWarp"]
`);
  assert.equal(valid.main, 'build/worker/shim.mjs');
  assert.equal(valid.compatibility, '2026-10-01');
  assert.deepEqual(valid.doBindings, [{ name: 'APP', class_name: 'OpenWarp' }]);
  assert.equal(sqliteBackedClasses(valid).length, 1);

  const missingMigration = parseToml(`
name = "openwarp"
main = "build/worker/shim.mjs"
compatibility_date = "2026-10-01"

[[durable_objects.bindings]]
name = "APP"
class_name = "OpenWarp"
`);
  assert.equal(sqliteBackedClasses(missingMigration).length, 0,
    'a Durable Object binding without new_sqlite_classes is not SQLite-backed');
});

test('Workers deployment declares a SQLite-backed Durable Object and a real entrypoint', () => {
  const candidates = configs(root);
  assert.ok(candidates.length > 0,
    'Workers runtime is absent: no Wrangler deployment config exists; native SQLite/Postgres alone does not satisfy dual runtime support');

  const deployments = candidates.map(filename => ({ filename, ...readDeployment(filename) }));

  const sqlite = deployments.filter(config => sqliteBackedClasses(config).length > 0);
  assert.ok(sqlite.length > 0,
    'Workers requires a Durable Object binding whose class is declared in new_sqlite_classes; D1 is not used because its async query API cannot serve the synchronous shared handlers');

  assert.ok(sqlite.every(config => typeof config.compatibility === 'string' && config.compatibility.trim()),
    'A Durable Object deployment must pin a compatibility_date');

  assert.ok(sqlite.some(config => typeof config.main === 'string' &&
    fs.existsSync(path.resolve(path.dirname(config.filename), config.main)) &&
    fs.statSync(path.resolve(path.dirname(config.filename), config.main)).isFile()),
  'The declared entrypoint must exist; build the Worker artifact (worker-build) before running this gate');

  for (const config of deployments) {
    const text = fs.readFileSync(config.filename, 'utf8');
    assert.equal(config.d1Bindings.length, 0,
      'D1 bindings are not used: the Workers build stores data in Durable Object SQLite');
    assert.ok(!/CLOUDFLARE_API_TOKEN|d1[\s_-]?rest/i.test(text),
      'The Worker must use runtime bindings only; a D1 REST credential or endpoint in the deployment config would bypass them');
  }
});
