import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export function run(files) {
  const browser = process.env.OPENWARP_TEST_BROWSER || 'chromium';
  if (!['chromium', 'firefox', 'webkit'].includes(browser)) throw new Error('OPENWARP_TEST_BROWSER must be chromium, firefox, or webkit');
  const child = spawn(process.execPath, [fileURLToPath(new URL('./node_modules/playwright/cli.js', import.meta.url)), 'test',
    `--config=${fileURLToPath(new URL('./playwright.config.mjs', import.meta.url))}`, `--project=${browser}`, ...files], {stdio: 'inherit'});
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => child.kill(signal));
  child.once('error', () => { console.error('Unable to start pinned Playwright. Run npm ci in tests/e2e.'); process.exitCode = 1; });
  child.once('exit', (code, signal) => { process.exitCode = signal ? 1 : code ?? 1; });
}
