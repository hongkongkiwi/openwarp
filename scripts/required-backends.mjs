import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const required = ['OPENWARP_TEST_POSTGRES_URL', 'OPENWARP_TEST_MYSQL_URL'];
const missing = required.filter(name => !process.env[name]?.trim());
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

let failed = false;
for (const target of ['postgres_backend', 'mysql_backend']) {
  const result = spawnSync('cargo', [
    'test', '-p', 'openwarp-server', '--test', target, '--', '--test-threads=2',
  ], {
    cwd: root,
    env: { ...process.env, CARGO_TERM_COLOR: 'never' },
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  const summaries = (result.stdout || '').match(/^test result: .*$/gm) || [];
  const summary = summaries.length === 1 && summaries[0].match(/^test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in .+$/);
  if (result.error || result.status !== 0 || !summary || Number(summary[1]) === 0) {
    console.error(`${target}: failed (Cargo exit ${result.status === null ? 'unavailable' : result.status}; required test summary not established)`);
    failed = true;
  } else {
    console.log(`${target}: ${summary[1]} passed; Cargo exit 0`);
  }
}
if (failed) process.exitCode = 1;
