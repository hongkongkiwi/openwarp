import assert from 'node:assert/strict';
import {test, expect, register, enter, appFixture, good} from '../fixture.mjs';

async function openApp(page, stack, actor, app, org) {
  await page.context().addCookies([{name: 'ow_session', value: actor.cookie, url: stack.base, httpOnly: true, sameSite: 'Lax'}]);
  await page.goto(stack.base);
  await page.locator(`#pickerlist [data-id="${org}"]`).click();
  await page.getByRole('button', {name: new RegExp(app.name)}).click();
}

test('client-keyed E2E write, reload unlock, member grant and revoke @critical', async ({page, stack, browser}, testInfo) => {
  const owner = await register(stack, 'crypto-owner@test.invalid');
  const member = await register(stack, 'crypto-member@test.invalid');
  const outsider = await register(stack, 'crypto-outsider@test.invalid');
  const invite = good(await stack.call('POST', `/api/orgs/${owner.org}/members`, owner.token, {email: member.email, role: 'developer'}), 'member invitation');
  good(await stack.call('POST', '/api/auth/accept-invite', member.token, {token: invite.invite_token}), 'member consent');
  const app = await appFixture(stack, owner, 'client-keyed-browser-app');
  const outsiderContext = await browser.newContext();
  try {
    const outsiderPage = await outsiderContext.newPage();
    await enter(outsiderPage, stack, outsider);
    await expect(outsiderPage.getByText('No apps yet', {exact: true})).toBeVisible();
    await expect(outsiderPage.getByRole('button', {name: new RegExp(app.name)})).toHaveCount(0);
    await outsiderPage.locator('#orgbtn').click();
    assert.equal(await outsiderPage.locator(`#orgmenu [data-id="${owner.org}"]`).count(), 0, 'outsider has no owner workspace in visible switcher');
  } finally { await outsiderContext.close(); }
  const key = 'BROWSER_CIPHER_ONLY', value = 'dummy-client-only-value';
  let outboundLeak = false, wrappedCreation = false;
  page.on('request', request => {
    const path = new URL(request.url()).pathname, body = request.postData() || '';
    if (/\/e2e(?:\/|$)/.test(path)) {
      if ([key, value, owner.kit, member.kit].some(secret => body.includes(secret))) outboundLeak = true;
      if (path.endsWith('/envs/e2e')) wrappedCreation = !!JSON.parse(body).wrapped_key;
    }
  });
  await enter(page, stack, owner); await page.getByRole('button', {name: new RegExp(app.name)}).click();
  await page.getByRole('button', {name: '+ E2E environment', exact: true}).click();
  const create = page.getByRole('dialog', {name: 'New end-to-end encrypted environment', exact: true});
  await create.getByRole('textbox', {name: 'Name', exact: true}).fill('client-vault');
  await create.getByLabel('Recovery kit (needed to wrap the new key)', {exact: true}).fill(owner.kit);
  const createdResponse = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/envs/e2e') && response.request().method() === 'POST');
  await create.getByRole('button', {name: 'Create E2E env', exact: true}).click();
  const created = await (await createdResponse).json();
  assert.equal(created.server_generated, false, 'client supplies environment key');
  await expect(page.getByText('No secrets here yet', {exact: true})).toBeVisible();
  await page.getByRole('button', {name: '+ New secret', exact: true}).click();
  const secret = page.getByRole('dialog', {name: 'New secret', exact: true});
  await secret.getByRole('textbox', {name: 'Key', exact: true}).fill(key);
  await secret.getByRole('textbox', {name: 'Value', exact: true}).fill(value);
  await secret.getByRole('button', {name: 'Stage secret', exact: true}).click();
  await page.getByRole('button', {name: 'Deploy changes', exact: true}).click();
  await expect(page.getByText('Deployed 1 secret', {exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Reveal', exact: true}).click();
  await expect(page.locator('#stable .val')).toHaveText(value);
  const ciphertext = good(await stack.call('GET', `/api/envs/${created.id}/e2e/secrets`, owner.token), 'stored ciphertext');
  assert.equal([key, value, owner.kit].some(plaintext => JSON.stringify(ciphertext).includes(plaintext)), false, 'API stores ciphertext only');
  assert.equal(wrappedCreation, true); assert.equal(outboundLeak, false, 'no plaintext in E2E requests');
  await page.reload(); await page.getByRole('button', {name: new RegExp(app.name)}).click();
  await page.getByRole('button', {name: 'client-vault · E2E', exact: true}).click();
  await expect(page.getByRole('button', {name: 'Unlock environment', exact: true})).toBeVisible();
  await page.getByLabel('Recovery kit', {exact: true}).fill(owner.kit);
  await page.getByRole('button', {name: 'Unlock environment', exact: true}).click();
  await expect(page.locator('#stable')).toContainText(key);
  await page.getByRole('button', {name: 'Access', exact: true}).click();
  const access = page.getByRole('dialog', {name: 'Environment access', exact: true});
  await access.getByRole('textbox', {name: 'Grant access by email', exact: true}).fill(member.email);
  await access.getByRole('button', {name: 'Grant access', exact: true}).click();
  await expect(access.getByText(member.email, {exact: true})).toBeVisible();
  await access.getByRole('button', {name: 'Close', exact: true}).click();
  const memberContext = await browser.newContext();
  const phase = description => testInfo.annotations.push({type: 'safe-phase', description});
  let memberFailure;
  try {
    phase('member context opened');
    const memberPage = await memberContext.newPage(); let errors = 0;
    memberPage.on('pageerror', () => errors++);
    await openApp(memberPage, stack, member, app, owner.org);
    phase('member app opened');
    await memberPage.getByRole('button', {name: 'client-vault · E2E', exact: true}).click();
    await memberPage.getByLabel('Recovery kit', {exact: true}).fill(member.kit);
    await memberPage.getByRole('button', {name: 'Unlock environment', exact: true}).click();
    await expect(memberPage.locator('#stable')).toContainText(key);
    await memberPage.getByRole('button', {name: 'Reveal', exact: true}).click();
    await expect(memberPage.locator('#stable .val')).toHaveText(value);
    assert.equal(errors, 0, 'member page errors');
    phase('member decrypted read verified');
  } catch (error) {
    memberFailure = error;
    phase('member journey failed before cleanup');
    const locations = (error.stack || '').split('\n').filter(line => /^\s+at .*\/specs\/crypto\.spec\.mjs:\d+:\d+/.test(line));
    for (const location of locations) phase(location);
    throw error;
  }
  finally {
    phase('member context closing');
    let timer;
    try {
      await Promise.race([memberContext.close(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('member context close timed out')), 10000); })]);
      phase('member context closed');
    } catch (error) { if (memberFailure) throw new AggregateError([memberFailure, error], 'member journey and cleanup failed'); throw error; }
    finally { clearTimeout(timer); }
  }
  await page.getByRole('button', {name: 'Access', exact: true}).click();
  const confirmed = page.waitForEvent('dialog').then(async dialog => { assert.match(dialog.message(), /Rotate/); await dialog.accept(); });
  await access.getByRole('button', {name: 'Remove access', exact: true}).click(); await confirmed;
  await expect(page.getByText('Access removed; rotate the key next', {exact: true})).toBeVisible();
  await access.getByRole('button', {name: 'Close', exact: true}).click();
  await expect(page.getByRole('button', {name: 'Rotate key now', exact: true})).toBeVisible();
  assert.equal(good(await stack.call('GET', `/api/envs/${created.id}/e2e/meta`, owner.token), 'rotation warning').rekey_required, true);
  assert.equal((await stack.call('GET', `/api/envs/${created.id}/e2e/secrets`, member.token)).status, 403, 'removed grant denies new reads');
  assert.equal((await stack.call('GET', `/api/envs/${created.id}/e2e/secrets`, outsider.token)).status, 403, 'outsider denied');
  // Revocation is not rotation and cannot erase keys or plaintext already copied.
  const after = good(await stack.call('GET', `/api/envs/${created.id}/e2e/secrets`, owner.token), 'ciphertext after revoke');
  assert.equal(JSON.stringify(after.secrets), JSON.stringify(ciphertext.secrets), 'revocation does not pretend to re-encrypt');
});
