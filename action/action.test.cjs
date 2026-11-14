'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const action = path.join(__dirname, 'index.js');
const token = 'dummy-action-token';
const environment = 'env /?#%';
const route = '/api/envs/env%20%2F%3F%23%25/export';
const initialOutput = 'previous=preserved\n';
const exportData = {
  text: 'COMPLEX="percent% carriage\\rline\\n::warning::not-command"\nEMPTY=\n',
  secrets: [
    { key: 'COMPLEX', value: 'percent% carriage\rline\n::warning::not-command' },
    { key: 'EMPTY', value: '' },
  ],
};

async function fixture(t, reply) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-action-'));
  await fs.chmod(directory, 0o700);
  const workspace = path.join(directory, 'workspace');
  const output = path.join(directory, 'github-output');
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.writeFile(output, initialOutput, { mode: 0o600 });
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, authorization: req.headers.authorization });
    if (req.url === route) reply(res);
    else {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(exportData));
    }
  });
  t.after(async () => {
    server.closeAllConnections();
    if (server.listening) await new Promise(resolve => server.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  async function run(inputs = {}) {
    // Do not inherit runner inputs, proxies, NODE_OPTIONS, or real credentials.
    const env = {
      GITHUB_WORKSPACE: workspace,
      GITHUB_OUTPUT: output,
      'INPUT_BASE-URL': `${base}///`,
      INPUT_TOKEN: token,
      'INPUT_ENV-ID': environment,
      ...inputs,
    };
    return new Promise((resolve, reject) => {
      execFile(process.execPath, [action], {
        cwd: workspace, env, encoding: 'utf8', timeout: 8000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
      }, (error, stdout, stderr) => {
        if (error && !Number.isInteger(error.code)) return reject(new Error('Action child failed to start or exceeded its time/output bound'));
        resolve({ code: error ? error.code : 0, stdout, stderr });
      });
    });
  }
  return { workspace, output, requests, run };
}

function replyJson(res, data = exportData) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function assertRequest(requests) {
  assert.deepEqual(requests, [{ method: 'GET', url: route, authorization: `Bearer ${token}` }]);
}

async function assertPrivateFile(filename) {
  if (process.platform !== 'win32') assert.equal((await fs.stat(filename)).mode & 0o777, 0o600);
}

test('action exports unchanged dotenv, encodes the environment, masks commands and appends count', { timeout: 15000 }, async t => {
  const f = await fixture(t, res => replyJson(res));
  const result = await f.run();
  assert.equal(result.code, 0, result.stderr);
  assertRequest(f.requests);
  const destination = path.join(f.workspace, '.env');
  assert.equal(await fs.readFile(destination, 'utf8'), exportData.text);
  await assertPrivateFile(destination);
  assert.equal(await fs.readFile(f.output, 'utf8'), `${initialOutput}count=2\n`);
  assert.deepEqual(result.stdout.trimEnd().split('\n'), [
    `::add-mask::${token}`,
    '::add-mask::percent%25 carriage%0Dline%0A::warning::not-command',
  ]);
});

test('action exports the JSON secrets array, tightens an existing file and keeps token masking when mask is false', { timeout: 15000 }, async t => {
  const f = await fixture(t, res => replyJson(res));
  const destination = path.join(f.workspace, 'nested', 'secrets.json');
  await fs.mkdir(path.dirname(destination));
  await fs.writeFile(destination, 'old contents');
  await fs.chmod(destination, 0o644);
  const result = await f.run({ 'INPUT_OUTPUT-FILE': 'nested/secrets.json', INPUT_FORMAT: 'json', INPUT_MASK: 'false' });
  assert.equal(result.code, 0, result.stderr);
  assertRequest(f.requests);
  assert.deepEqual(JSON.parse(await fs.readFile(destination, 'utf8')), exportData.secrets);
  await assertPrivateFile(destination);
  assert.equal(await fs.readFile(f.output, 'utf8'), `${initialOutput}count=2\n`);
  assert.equal(result.stdout, `::add-mask::${token}\n`);
});

for (const failure of [
  { name: 'HTTP denial', reply(res) { res.writeHead(403); res.end('fixture access denied'); }, diagnostic: /HTTP 403/ },
  { name: 'malformed JSON', reply(res) { res.writeHead(200); res.end('{not json'); } },
  { name: 'invalid export shape', reply(res) { replyJson(res, { text: 'must not be written', secrets: [{ value: 42 }] }); }, diagnostic: /Invalid OpenWarp export response/ },
  { name: 'redirect', reply(res) { res.writeHead(302, { Location: '/redirect-destination' }); res.end(); } },
]) {
  test(`action rejects ${failure.name} without writing an export or count`, { timeout: 15000 }, async t => {
    const f = await fixture(t, failure.reply);
    const result = await f.run();
    assert.notEqual(result.code, 0);
    assertRequest(f.requests);
    assert.match(result.stdout, /(?:^|\n)::error::/);
    if (failure.diagnostic) assert.match(result.stdout, failure.diagnostic);
    await assert.rejects(fs.stat(path.join(f.workspace, '.env')), { code: 'ENOENT' });
    assert.equal(await fs.readFile(f.output, 'utf8'), initialOutput);
  });
}
