import assert from 'node:assert/strict';
import {test, expect, register, enter, appFixture, good} from '../fixture.mjs';

test('console navigation, theme and language persist with user data @critical', async ({page, stack}) => {
  const actor = await register(stack, 'console@test.invalid');
  const app = await appFixture(stack, actor, 'Untranslated user app');
  await enter(page, stack, actor);
  await expect(page.getByRole('button', {name: new RegExp(app.name)})).toBeVisible();
  // Preserve the old first-four navigation pass, including app-scoped Integrations.
  for (const view of ['apps', 'access', 'integrations', 'audit']) {
    await page.locator(`[data-nav="${view}"]`).click();
    await expect(page.locator('#shell')).toBeVisible();
    await expect(page.getByText('This view could not load', {exact: true})).toHaveCount(0);
  }
  await page.locator('[data-nav="apps"]').click();
  await page.locator('[data-themetoggle]:visible').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme-pref', 'light');
  assert.equal(await page.evaluate(() => localStorage.getItem('ow_theme')), 'light');
  await page.reload(); await expect(page.locator('html')).toHaveAttribute('data-theme-pref', 'light');
  await page.locator('[data-themetoggle]:visible').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  const language = page.locator('.langsel:visible');
  const alt = await language.locator('option').evaluateAll(options => options.map(option => option.value).find(value => value && value !== 'en' && value !== 'system'));
  assert.ok(alt, 'alternative language exists');
  const before = await page.locator('#authtitle').textContent();
  await language.selectOption(alt);
  await expect(page.locator('#authtitle')).not.toHaveText(before);
  const translated = await page.locator('#authtitle').textContent();
  await page.reload(); await expect(page.locator('#authtitle')).toHaveText(translated);
  await expect(page.locator('.appcard h3')).toHaveText(app.name);
});

test('keyboard mobile app creation and destructive cancellation', async ({page, stack}) => {
  const actor = await register(stack, 'keyboard@test.invalid');
  await enter(page, stack, actor);
  await expect(page.getByText('No apps yet', {exact: true})).toBeVisible();
  const create = page.getByRole('button', {name: 'Create your first app', exact: true});
  await create.focus(); await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', {name: 'New app', exact: true});
  const name = dialog.getByRole('textbox', {name: 'App name', exact: true});
  await expect(name).toBeFocused(); await page.keyboard.type('keyboard-mobile-app');
  await page.keyboard.press('Tab'); await page.keyboard.press('Tab'); await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await page.getByRole('button', {name: /keyboard-mobile-app/}).click();
  await page.getByRole('button', {name: 'App settings', exact: true}).click();
  const deleted = page.waitForEvent('dialog').then(async confirm => {
    assert.equal(confirm.type(), 'confirm'); assert.match(confirm.message(), /cannot be undone/); await confirm.dismiss();
  });
  await page.getByRole('button', {name: 'Delete app', exact: true}).click();
  await deleted;
  const apps = good(await stack.call('GET', `/api/orgs/${actor.org}/apps`, actor.token), 'app survives cancellation');
  assert.equal(apps.length, 1);
  await page.keyboard.press('Escape');
  await page.setViewportSize({width: 390, height: 844});
  await page.locator('#navtoggle').click();
  await expect(page.locator('aside')).toHaveClass(/open/);
  await page.locator('[data-nav="settings"]').click();
  await expect(page.locator('aside')).not.toHaveClass(/open/);
  await expect(page.locator('#navtoggle')).toHaveAttribute('aria-expanded', 'false');
});
