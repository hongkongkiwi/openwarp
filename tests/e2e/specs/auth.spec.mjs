import assert from 'node:assert/strict';
import {test, expect, register, good, poll} from '../fixture.mjs';

test.describe('sign-in/out', () => {
test.use({anonymousBootstraps: 3});
test('real password sign-in, sign-out and fresh-context isolation @critical', async ({page, stack, browser}) => {
  const actor = await register(stack, 'auth@test.invalid');
  await page.goto(stack.base);
  await page.getByRole('textbox', {name: 'Email', exact: true}).fill(actor.email);
  await page.locator('#pw').fill(actor.password);
  await page.locator('#authbtn').click();
  await expect(page.locator('#shell')).toBeVisible();
  await page.locator('#orgbtn').click();
  await page.getByRole('menuitem', {name: 'Sign out', exact: true}).click();
  await expect(page.locator('#auth')).toBeVisible();
  await page.reload(); await expect(page.locator('#auth')).toBeVisible();
  const fresh = await browser.newContext();
  try { const isolated = await fresh.newPage(); await isolated.goto(stack.base); await expect(isolated.locator('#auth')).toBeVisible(); }
  finally { await fresh.close(); }
});

});

test.describe('signup', () => {
test.use({anonymousBootstraps: 1});
test('visible signup recovery kit and verification before sign-in @critical', async ({page, stack}) => {
  await page.goto(stack.base);
  await page.locator('#segreg').click();
  await page.getByRole('textbox', {name: 'Email', exact: true}).fill('signup@test.invalid');
  await page.locator('#pw').fill('signup-fixture-password');
  await page.locator('#authbtn').click();
  const dialog = page.getByRole('dialog', {name: 'Check your email', exact: true});
  await expect(dialog).toBeVisible();
  const kit = await dialog.getByRole('textbox', {name: 'Recovery kit', exact: true}).inputValue();
  assert.equal(Buffer.from(kit, 'base64').length, 32, 'recovery kit is an X25519 private key');
  await dialog.getByRole('button', {name: 'I saved it', exact: true}).click();
  const link = await poll(() => stack.mails.map(mail => JSON.stringify(mail).match(/\/api\/auth\/verify\?token=[A-Za-z0-9_-]+/)?.[0]).find(Boolean), 'signup verification');
  good(await stack.call('GET', link), 'signup verification');
  await page.locator('#seglogin').click(); await page.locator('#authbtn').click();
  await expect(page.locator('#shell')).toBeVisible();
  assert.equal(await page.evaluate(() => Object.keys(localStorage).some(key => /kit|private|token/i.test(key))), false, 'no kit or token localStorage entry');
});
});
