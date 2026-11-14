import {defineConfig} from 'playwright/test';

// Playwright otherwise captures the failing page's accessible DOM, including kit text.
process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  workers: 1,
  retries: 0,
  timeout: 120000,
  expect: {timeout: 15000},
  reporter: './safe-reporter.mjs',
  outputDir: './test-results',
  preserveOutput: 'never',
  use: {
    headless: true,
    viewport: {width: 1440, height: 1000},
    locale: 'en-US',
    colorScheme: 'light',
    screenshot: 'off',
    trace: 'off',
    video: 'off',
  },
  projects: [
    {name: 'chromium', use: {browserName: 'chromium'}},
    {name: 'firefox', grep: /@critical/, use: {browserName: 'firefox'}},
    {name: 'webkit', grep: /@critical/, use: {browserName: 'webkit'}},
  ],
});
