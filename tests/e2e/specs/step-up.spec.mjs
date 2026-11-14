import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {test, expect, register, enter, appFixture, good, poll, ROOT} from '../fixture.mjs';

// Together these preserve the eight checks from the original step-up.mjs.
test('step-up cancellations, focus, email and Major recovery proof @critical', async ({page, stack}, testInfo) => {
  const actor = await register(stack, 'step-up-browser@test.invalid');
  const app = await appFixture(stack, actor, 'step-up-acceptance');
  const settingsPath = `/api/orgs/${actor.org}/settings`, secretsPath = `/api/envs/${app.env.id}/secrets`;
  const initial = good(await stack.call('GET', settingsPath, actor.token), 'initial settings');
  const requests = [], responses = [];
  page.on('request', request => requests.push({path: new URL(request.url()).pathname, method: request.method(), grant: !!request.headers()['x-openwarp-step-up']}));
  page.on('response', response => responses.push({path: new URL(response.url()).pathname, status: response.status()}));
  const count = (path, method) => requests.filter(request => request.path === path && request.method === method).length;
  const wait = (path, method, status) => page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === method && response.status() === status);
  await enter(page, stack, actor);
  await page.getByRole('button', {name: /Settings$/}).click();
  const save = page.getByRole('button', {name: 'Save settings', exact: true});
  await page.getByRole('checkbox', {name: 'Warn when a secret value is reused elsewhere in this workspace', exact: true}).setChecked(!initial.reuse_check);
  const dialog = page.getByRole('dialog', {name: 'Confirm action', exact: true});
  const email = dialog.getByRole('textbox', {name: 'Emailed code', exact: true});
  const verify = dialog.getByRole('button', {name: 'Verify', exact: true}), cancel = dialog.getByRole('button', {name: 'Cancel', exact: true});
  const captureBlankModal = async label => {
    if (process.env.OPENWARP_TEST_BLANK_MODAL_SCREENSHOTS !== '1') return;
    for (const input of await dialog.locator('input,textarea').all()) assert.equal(await input.inputValue(), '', 'capture requires blank factor fields');
    assert.equal(await dialog.getByRole('textbox', {name: /Recovery kit|Value/}).count(), 0, 'no secret editor in capture');
    const dir = join(ROOT, '.agents/state/browser-acceptance/blank-modals');
    mkdirSync(dir, {recursive: true});
    await dialog.screenshot({path: join(dir, `${testInfo.project.name}-${label}.png`)});
  };
  const focusDiagnostic = async phase => {
    const state = await page.evaluate(() => {
      const describe = element => ({tag: element?.tagName || null, id: ['modal', 'step-up-email', 'set-reuse'].includes(element?.id) ? element.id : null,
        button: element?.tagName === 'BUTTON' ? ['Save settings', 'Cancel', 'Verify'].find(label => element.textContent === label) || 'other' : null});
      return {active: describe(document.activeElement), previous: describe(LASTFOCUS)};
    });
    testInfo.annotations.push({type: 'safe-focus', description: JSON.stringify({phase, ...state})});
  };
  const open = async () => {
    const before = stack.mails.length, challenged = wait(settingsPath, 'PUT', 428);
    await save.focus(); await expect(save).toBeFocused();
    await focusDiagnostic('before keyboard Save activation');
    await page.keyboard.press('Enter'); await challenged; await expect(email).toBeVisible();
    await focusDiagnostic('verification open');
    return before;
  };
  for (const method of ['Cancel', 'Escape', 'backdrop']) {
    const writes = count(settingsPath, 'PUT'), verifications = count('/api/auth/step-up/verify', 'POST');
    await open(); await expect(email).toBeFocused();
    if (method === 'Cancel') {
      await page.keyboard.press('Shift+Tab'); await expect(cancel).toBeFocused();
      await page.keyboard.press('Tab'); await expect(email).toBeFocused();
      await page.keyboard.press('Tab');
      testInfo.annotations.push({type: 'safe-focus', description: await page.evaluate(() => {
        const active = document.activeElement;
        return JSON.stringify({tag: active?.tagName, factor: active?.id === 'step-up-email', button: active?.tagName === 'BUTTON' ? ['Cancel', 'Verify'].find(label => active.textContent === label) || 'other' : null});
      })});
      await expect(verify).toBeFocused();
      await captureBlankModal('email-desktop-verify-focus');
      await page.keyboard.press('Tab'); await expect(cancel).toBeFocused();
      await page.keyboard.press('Tab'); await expect(email).toBeFocused();
      await page.setViewportSize({width: 390, height: 844});
      const box = await dialog.boundingBox();
      assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= 391 && box.y + box.height <= 845, 'verification dialog fits mobile');
      await captureBlankModal('email-mobile-input-focus');
      await page.setViewportSize({width: 1440, height: 1000}); await cancel.click();
    } else if (method === 'Escape') await page.keyboard.press('Escape');
    else await page.locator('#modalwrap').click({position: {x: 4, y: 4}});
    await expect(dialog).toBeHidden(); await expect(page.getByText('Verification cancelled', {exact: true}).first()).toBeVisible();
    await focusDiagnostic(`after ${method} cancellation`);
    await expect(save).toBeFocused();
    assert.equal(good(await stack.call('GET', settingsPath, actor.token), 'cancelled settings').reuse_check, initial.reuse_check);
    assert.equal(count(settingsPath, 'PUT'), writes + 1, `${method} never replays`);
    assert.equal(count('/api/auth/step-up/verify', 'POST'), verifications, `${method} never verifies`);
  }
  const before = await open();
  const code = await poll(() => stack.mails.slice(before).map(mail => mail.text?.match(/\b\d{6}\b/)?.[0]).find(Boolean), 'step-up code');
  const writes = count(settingsPath, 'PUT');
  await email.fill(code); const saved = wait(settingsPath, 'PUT', 200); await verify.click(); await saved;
  await expect(dialog).toBeHidden(); await expect(page.getByText('Settings saved', {exact: true})).toBeVisible();
  assert.equal(count(settingsPath, 'PUT'), writes + 1, 'email proof replays once');
  assert.equal(requests.filter(request => request.path === settingsPath && request.method === 'PUT' && request.grant).length, 1);
  assert.equal(good(await stack.call('GET', settingsPath, actor.token), 'saved settings').reuse_check, !initial.reuse_check);
  const setup = good(await stack.call('POST', '/api/me/totp/setup', actor.token, {}), 'TOTP setup');
  let bits = 0, value = 0; const key = [];
  for (const char of setup.secret) { value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char); bits += 5; if (bits >= 8) { key.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', Buffer.from(key)).update(counter).digest();
  good(await stack.call('POST', '/api/me/totp/verify', actor.token, {code: String((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0')}), 'enable TOTP');
  assert.ok(setup.recovery_codes?.[0]);
  await page.getByRole('button', {name: /Apps$/}).click(); await page.getByRole('button', {name: new RegExp(app.name)}).click();
  await page.getByRole('button', {name: '+ New secret', exact: true}).click();
  const secret = page.getByRole('dialog', {name: 'New secret', exact: true});
  await secret.getByRole('textbox', {name: 'Key', exact: true}).fill('STEP_UP_ACCEPTANCE');
  await secret.getByRole('textbox', {name: 'Value', exact: true}).fill('dummy-browser-value');
  await secret.getByRole('button', {name: 'Stage secret', exact: true}).click();
  const challenged = wait(secretsPath, 'PUT', 428); await page.getByRole('button', {name: 'Deploy changes', exact: true}).click(); await challenged;
  const factor = dialog.getByRole('textbox', {name: 'Authenticator or recovery code', exact: true});
  await expect(factor).toBeVisible(); await expect(factor).toBeFocused(); assert.equal(await email.count(), 0);
  await page.setViewportSize({width: 390, height: 844});
  const majorBox = await dialog.boundingBox();
  assert.ok(majorBox && majorBox.x >= 0 && majorBox.y >= 0 && majorBox.x + majorBox.width <= 391 && majorBox.y + majorBox.height <= 845, 'Major dialog fits mobile');
  await page.setViewportSize({width: 1440, height: 1000});
  const majorWrites = count(secretsPath, 'PUT'); await factor.fill(setup.recovery_codes[0]);
  const deployed = wait(secretsPath, 'PUT', 200); await verify.click(); await deployed;
  await expect(dialog).toBeHidden(); await expect(page.getByText('Deployed 1 secret', {exact: true})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Deploy changes', exact: true})).toBeHidden();
  assert.equal(count(secretsPath, 'PUT'), majorWrites + 1);
  assert.equal(good(await stack.call('GET', secretsPath, actor.token), 'deployed secret').secrets.filter(secret => secret.key === 'STEP_UP_ACCEPTANCE' && secret.value === 'dummy-browser-value').length, 1);
  assert.equal(responses.filter(response => response.path === '/api/auth/step-up/verify' && response.status === 200).length, 2);
});
