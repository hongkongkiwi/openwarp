'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const wrapper = path.join(root, 'scripts/required-backends.mjs');
const targets = ['postgres_backend', 'mysql_backend'];
const fixtureUrls = {
  OPENWARP_TEST_POSTGRES_URL: 'postgres://fixture:dummy-pg-password@127.0.0.1:1/fixture',
  OPENWARP_TEST_MYSQL_URL: 'mysql://fixture:dummy-my-password@127.0.0.1:1/fixture',
};

// The only executable on the child's PATH records Cargo calls and emits libtest output.
const fakeCargo = `#!${process.execPath}
'use strict';
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FIXTURE_RECORD, JSON.stringify({
  args,
  postgres: process.env.OPENWARP_TEST_POSTGRES_URL,
  mysql: process.env.OPENWARP_TEST_MYSQL_URL,
}) + '\\n', { mode: 0o600 });
const selected = args.flatMap((arg, index) => arg === '--test' ? [args[index + 1]] : []);
let failed = false;
for (const target of selected) {
  const scenario = process.env.FIXTURE_SCENARIO;
  const affected = process.env.FIXTURE_TARGET === target;
  process.stderr.write('    Finished \\u0060test\\u0060 profile [unoptimized + debuginfo] target(s) in 0.10s\\n');
  process.stderr.write('     Running tests/' + target + '.rs (target/debug/deps/' + target + '-0123456789abcdef)\\n');
  if (affected && scenario === 'missing-summary') continue;
  const name = target + '_round_trip';
  if (affected && scenario === 'zero') {
    process.stdout.write('\\nrunning 0 tests\\n\\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\\n\\n');
  } else if (affected && scenario === 'ignored-only') {
    process.stdout.write('\\nrunning 1 test\\ntest ' + name + ' ... ignored, fixture unavailable\\n\\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n\\n');
  } else if (affected && scenario === 'ignored') {
    process.stdout.write('\\nrunning 2 tests\\ntest ' + name + ' ... ok\\ntest fixture_second_case ... ignored, fixture unavailable\\n\\ntest result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\\n\\n');
  } else if (affected && scenario === 'filtered') {
    process.stdout.write('\\nrunning 1 test\\ntest ' + name + ' ... ok\\n\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\\n\\n');
  } else if (affected && scenario === 'failure') {
    failed = true;
    process.stdout.write('\\nrunning 1 test\\ntest ' + name + ' ... FAILED\\n\\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\\n\\n');
    process.stderr.write('error: fixture backend test failed\\n');
  } else {
    process.stdout.write('\\nrunning 1 test\\ntest ' + name + ' ... ok\\n\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\\n\\n');
  }
}
process.exitCode = failed ? 101 : 0;
`;

async function runFixture(t, { missing, value, scenario = 'success', target = '' } = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'openwarp-backend-gate-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const bin = path.join(directory, 'bin');
  const record = path.join(directory, 'calls.jsonl');
  await fs.mkdir(bin, { mode: 0o700 });
  await fs.writeFile(path.join(bin, 'cargo'), fakeCargo, { mode: 0o700 });
  const env = {
    PATH: bin,
    HOME: directory,
    ...fixtureUrls,
    FIXTURE_RECORD: record,
    FIXTURE_SCENARIO: scenario,
    FIXTURE_TARGET: target,
    CARGO_TERM_COLOR: 'never',
  };
  if (missing) {
    if (value === undefined) delete env[missing];
    else env[missing] = value;
  }
  const result = await new Promise((resolve, reject) => {
    execFile(process.execPath, [wrapper], {
      cwd: root, env, encoding: 'utf8', timeout: 8000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
    }, (error, stdout, stderr) => {
      if (error && !Number.isInteger(error.code)) return reject(new Error('Backend wrapper child failed to start or exceeded its time/output bound'));
      resolve({ code: error ? error.code : 0, stdout, stderr });
    });
  });
  let calls = [];
  try {
    calls = (await fs.readFile(record, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const log = result.stdout + result.stderr;
  for (const url of Object.values(fixtureUrls)) {
    assert.ok(!log.includes(url), 'wrapper logs must not include fixture database URLs');
  }
  for (const password of ['dummy-pg-password', 'dummy-my-password']) {
    assert.ok(!log.includes(password), 'wrapper logs must not include fixture database passwords');
  }
  return { ...result, calls, log };
}

function assertCargoTargets(calls) {
  const selected = [];
  assert.ok(calls.length === 1 || calls.length === 2, 'run both targets together or as two Cargo calls');
  for (const call of calls) {
    assert.equal(call.postgres, fixtureUrls.OPENWARP_TEST_POSTGRES_URL, 'pass the PostgreSQL fixture URL unchanged');
    assert.equal(call.mysql, fixtureUrls.OPENWARP_TEST_MYSQL_URL, 'pass the MySQL fixture URL unchanged');
    const separator = call.args.indexOf('--');
    assert.ok(separator > 0, 'Cargo must pass arguments to the test harness');
    assert.deepEqual(call.args.slice(separator + 1), ['--test-threads=2']);
    const cargoArgs = call.args.slice(0, separator);
    assert.equal(cargoArgs.shift(), 'test');
    let packages = 0;
    while (cargoArgs.length) {
      const arg = cargoArgs.shift();
      if (arg === '-p' || arg === '--package') {
        assert.equal(cargoArgs.shift(), 'openwarp-server');
        packages++;
      } else if (arg === '--test') selected.push(cargoArgs.shift());
      else assert.equal(arg, '--all-features', 'do not substitute filters or unrelated Cargo targets');
    }
    assert.equal(packages, 1, 'select the openwarp-server package');
  }
  assert.deepEqual(selected.sort(), [...targets].sort(), 'run exactly both required integration targets');
}

test('required backend lane has an executable wrapper and fails closed on absent coverage', { timeout: 180000 }, async t => {
  const present = await fs.stat(wrapper).then(stat => stat.isFile(), error => {
    if (error.code === 'ENOENT') return false;
    throw error;
  });
  assert.ok(present, 'Required backend wrapper is absent: scripts/required-backends.mjs has not been implemented; behavioral fixtures cannot run');

  for (const missing of Object.keys(fixtureUrls)) {
    for (const [label, value] of [['unset', undefined], ['empty', ''], ['whitespace-only', ' \t\n ']]) {
      await t.test(`rejects ${label} ${missing} before Cargo`, async t => {
        const result = await runFixture(t, { missing, value });
        assert.notEqual(result.code, 0);
        assert.match(result.log, new RegExp(missing));
        assert.deepEqual(result.calls, [], 'missing fixtures must fail before invoking Cargo');
      });
    }
  }

  await t.test('runs both exact backend targets with fixture URLs and two test threads', async t => {
    const result = await runFixture(t);
    assert.equal(result.code, 0, result.log);
    assertCargoTargets(result.calls);
  });

  for (const target of targets) {
    for (const scenario of ['failure', 'zero', 'ignored-only', 'ignored', 'filtered', 'missing-summary']) {
      await t.test(`rejects ${target} ${scenario} even if the other backend passes`, async t => {
        const result = await runFixture(t, { target, scenario });
        assert.notEqual(result.code, 0, 'successful process exit alone is not proof of executed backend tests');
        assert.ok(result.calls.length > 0, 'the fake Cargo executable must have exercised the wrapper');
      });
    }
  }
});
