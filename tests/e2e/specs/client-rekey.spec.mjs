import assert from 'node:assert/strict';
import {test, expect, register, enter, appFixture, good, poll} from '../fixture.mjs';

const secret = {key: 'CLIENT_REKEY_BROWSER_ONLY', value: 'dummy-browser-rekey-value', path: '/browser-private-rekey-path'};

function watchPlaintext(page, actors) {
  let leaks = 0, clientWrapped = false;
  const rekeys = [];
  page.on('request', request => {
    const path = new URL(request.url()).pathname, body = request.postData() || '';
    if ([secret.key, secret.value, secret.path, ...actors.map(actor => actor.kit)].some(value => (request.url() + body).includes(value))) leaks++;
    if (request.method() === 'POST' && path.endsWith('/envs/e2e')) clientWrapped = !!JSON.parse(body).wrapped_key;
    if (request.method() === 'POST' && path.endsWith('/e2e/rekey')) {
      const payload = JSON.parse(body);
      rekeys.push({path, generation: payload.expected_generation, membership: payload.membership_version,
        snapshot: typeof payload.snapshot_token === 'string' && payload.snapshot_token.length > 0,
        recipients: (payload.grants || []).map(grant => grant.user_id)});
    }
  });
  return {rekeys, check() {
    assert.equal(leaks, 0, 'no recovery kit or secret plaintext in browser requests');
    assert.equal(clientWrapped, true, 'environment creation supplies a client-wrapped key');
  }};
}

// The fixture audits its own page only; a second authenticated page gets the same zero-error gates.
function guardSecondaryPage(page, stack, actors, testInfo) {
  let pageErrors = 0, consoleErrors = 0, externalRequests = 0, failedResponses = 0, plaintextRequests = 0;
  page.on('pageerror', () => pageErrors++);
  page.on('console', message => {
    if (message.type() === 'error' && !/^Failed to load resource: the server responded with a status of 428\b/.test(message.text())) consoleErrors++;
  });
  page.on('request', request => {
    if (!request.url().startsWith(stack.base + '/')) externalRequests++;
    if ([secret.key, secret.value, secret.path, ...actors.map(actor => actor.kit)].some(value => (request.url() + (request.postData() || '')).includes(value))) plaintextRequests++;
  });
  page.on('response', response => { if (response.status() >= 400 && response.status() !== 428) failedResponses++; });
  return () => {
    testInfo.annotations.push({type: 'safe-browser-counts', description: JSON.stringify({secondaryPage: true, pageErrors, consoleErrors, externalRequests, failedResponses, plaintextRequests})});
    assert.equal(pageErrors, 0, 'secondary page exception count');
    assert.equal(consoleErrors, 0, 'secondary page console error count');
    assert.equal(externalRequests, 0, 'secondary page external request count');
    assert.equal(failedResponses, 0, 'secondary page unexpected failed response count');
    assert.equal(plaintextRequests, 0, 'secondary page secret-bearing request count');
  };
}

async function actorsAndApp(stack, name) {
  const owner = await register(stack, `${name}-owner@test.invalid`);
  const member = await register(stack, `${name}-member@test.invalid`);
  const invite = good(await stack.call('POST', `/api/orgs/${owner.org}/members`, owner.token, {email: member.email, role: 'developer'}), 'member invitation');
  good(await stack.call('POST', '/api/auth/accept-invite', member.token, {token: invite.invite_token}), 'member consent');
  return {owner, member, app: await appFixture(stack, owner, name)};
}

async function createVault(page, stack, owner, app) {
  await enter(page, stack, owner);
  await page.getByRole('button').filter({has: page.getByRole('heading', {name: app.name, exact: true})}).click();
  await page.getByRole('button', {name: '+ E2E environment', exact: true}).click();
  const create = page.getByRole('dialog', {name: 'New end-to-end encrypted environment', exact: true});
  await create.getByRole('textbox', {name: 'Name', exact: true}).fill('automatic-rekey-vault');
  await create.getByLabel('Recovery kit (needed to wrap the new key)', {exact: true}).fill(owner.kit);
  const response = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/envs/e2e') && response.request().method() === 'POST');
  await create.getByRole('button', {name: 'Create E2E env', exact: true}).click();
  const result = await response;
  const created = good({status: result.status(), json: await result.json()}, 'client-keyed environment');
  assert.equal(created.server_generated, false, 'server never generates the environment key');
  await expect(page.getByText('No secrets here yet', {exact: true})).toBeVisible();
  await page.getByRole('button', {name: '+ New secret', exact: true}).click();
  const editor = page.getByRole('dialog', {name: 'New secret', exact: true});
  await editor.getByRole('textbox', {name: 'Key', exact: true}).fill(secret.key);
  await editor.getByRole('textbox', {name: 'Value', exact: true}).fill(secret.value);
  await editor.getByRole('textbox', {name: 'Path', exact: true}).fill(secret.path);
  await editor.getByRole('button', {name: 'Stage secret', exact: true}).click();
  await page.getByRole('button', {name: 'Deploy changes', exact: true}).click();
  await expect(page.getByText('Deployed 1 secret', {exact: true})).toBeVisible();
  return created.id;
}

async function grantMember(page, member) {
  await page.getByRole('button', {name: 'Access', exact: true}).click();
  const access = page.getByRole('dialog', {name: 'Environment access', exact: true});
  await access.getByRole('textbox', {name: 'Grant access by email', exact: true}).fill(member.email);
  await access.getByRole('button', {name: 'Grant access', exact: true}).click();
  await expect(access.getByText(member.email, {exact: true})).toBeVisible();
  await access.getByRole('button', {name: 'Close', exact: true}).click();
}

async function openVault(page, app) {
  await page.getByRole('button').filter({has: page.getByRole('heading', {name: app.name, exact: true})}).click();
  await page.getByRole('button', {name: 'automatic-rekey-vault · E2E', exact: true}).click();
}

async function unlockVault(page, actor) {
  await expect(page.getByRole('button', {name: 'Unlock environment', exact: true})).toBeVisible();
  await page.getByLabel('Recovery kit', {exact: true}).fill(actor.kit);
  await page.getByRole('button', {name: 'Unlock environment', exact: true}).click();
  await expect(page.locator('#stable')).toContainText(secret.key);
}

async function meta(stack, id, token) {
  return good(await stack.call('GET', `/api/envs/${id}/e2e/meta`, token), 'environment metadata');
}

async function rotated(stack, id, token, generation) {
  return poll(async () => {
    const current = await meta(stack, id, token);
    return current.key_generation === generation + 1 && current.rekey_required === false && current;
  }, 'automatic client rekey generation and cleared pending state');
}

async function ciphertext(stack, id, token) {
  const result = good(await stack.call('GET', `/api/envs/${id}/e2e/secrets`, token), 'ciphertext read-back');
  assert.equal([secret.key, secret.value, secret.path].some(value => JSON.stringify(result).includes(value)), false, 'ciphertext API contains no secret plaintext');
  return result;
}

async function currentKeyDecrypts(page, actor, payload) {
  assert.equal(await page.evaluate(async ({kit, payload, expected}) => {
    const key = await OW.decryptAsymmetric(kit, payload.wrapped_key), decode = bytes => new TextDecoder().decode(bytes);
    if (key.length !== 32 || payload.secrets.length !== 1) return false;
    const row = payload.secrets[0];
    return decode(await OW.decryptSymmetric(key, row.key_enc)) === expected.key &&
      decode(await OW.decryptSymmetric(key, row.value_enc)) === expected.value &&
      decode(await OW.decryptSymmetric(key, row.path_enc)) === expected.path;
  }, {kit: actor.kit, payload, expected: secret}), true, 'current holder locally unwraps and decrypts every secret field');
}

function sameRecordsReencrypted(before, after) {
  assert.equal(after.secrets.length, before.secrets.length, 'rotation preserves the complete record set');
  for (const previous of before.secrets) {
    const current = after.secrets.find(row => row.id === previous.id);
    assert.ok(current, 'rotation preserves secret identity');
    assert.equal(current.key_hash, previous.key_hash, 'rotation preserves blind record identity');
    assert.equal(current.version, previous.version + 1, 'rotation advances each stored version once');
    for (const field of ['key_enc', 'value_enc', 'path_enc']) assert.notEqual(current[field], previous[field], 'rotation replaces each ciphertext field');
  }
}

function snapshotRequest(observation, id, before, membership, remaining, removed) {
  assert.equal(observation.rekeys.length, 1, 'one automatic rekey request without a manual rotation action');
  const request = observation.rekeys[0];
  assert.equal(request.path, `/api/envs/${id}/e2e/rekey`, 'automatic rotation targets the selected environment');
  assert.equal(request.generation, before.key_generation, 'automatic rotation uses the current generation fence');
  assert.equal(request.membership, membership, 'automatic rotation uses the post-revocation membership fence');
  assert.equal(request.snapshot, true, 'automatic rotation supplies a snapshot CAS token');
  assert.deepEqual(request.recipients, [remaining.id], 'only the surviving holder gets a replacement wrap');
  assert.equal(request.recipients.includes(removed.id), false, 'removed holder receives no replacement wrap');
}

test('UI grant revocation automatically rekeys and rejects the copied old key @critical', async ({page, stack, browser}, testInfo) => {
  const {owner, member, app} = await actorsAndApp(stack, 'automatic-client-rekey');
  const observation = watchPlaintext(page, [owner, member]);
  const id = await createVault(page, stack, owner, app);
  await grantMember(page, member);
  const before = await meta(stack, id, owner.token), stored = await ciphertext(stack, id, owner.token);
  assert.equal(before.rekey_required, false, 'adding a grant does not create pending rotation');
  const context = await browser.newContext();
  let checkSecondary;
  try {
    const memberPage = await context.newPage();
    checkSecondary = guardSecondaryPage(memberPage, stack, [owner, member], testInfo);
    await memberPage.context().addCookies([{name: 'ow_session', value: member.cookie, url: stack.base, httpOnly: true, sameSite: 'Lax'}]);
    await memberPage.goto(stack.base);
    await memberPage.locator(`#pickerlist [data-id="${owner.org}"]`).click();
    await openVault(memberPage, app);
    await unlockVault(memberPage, member);
    await memberPage.getByRole('button', {name: 'Reveal', exact: true}).click();
    await expect(memberPage.locator('#stable .val')).toHaveText(secret.value);
    const copiedKeyStatus = await memberPage.evaluate(async ({id, kit, expected}) => {
      const response = await fetch(`/api/envs/${id}/e2e/secrets`, {credentials: 'same-origin'});
      if (response.status !== 200) return `fetch:${response.status}`;
      const saved = await response.json();
      if (saved.secrets.length !== 1) return `count:${saved.secrets.length}`;
      let oldKey;
      try { oldKey = await OW.decryptAsymmetric(kit, saved.wrapped_key); } catch { return 'unwrap'; }
      if (oldKey.length !== 32) return 'keylen';
      const decode = bytes => new TextDecoder().decode(bytes), original = saved.secrets[0];
      try { if (decode(await OW.decryptSymmetric(oldKey, original.key_enc)) !== expected.key) return 'key'; } catch { return 'key'; }
      try { if (decode(await OW.decryptSymmetric(oldKey, original.value_enc)) !== expected.value) return 'value'; } catch { return 'value'; }
      try { if (decode(await OW.decryptSymmetric(oldKey, original.path_enc)) !== expected.path) return 'path'; } catch { return 'path'; }
      // Retain a copied key only inside this browser realm; report safe status codes, never key bytes or plaintext.
      globalThis.clientRekeyCopiedKeyProbe = async next => {
        let rejected = 0;
        for (const row of next.secrets) for (const field of ['key_enc', 'value_enc', 'path_enc']) {
          try { await OW.decryptSymmetric(oldKey, row[field]); } catch { rejected++; }
        }
        return {copiedStillReadable: decode(await OW.decryptSymmetric(oldKey, original.value_enc)) === expected.value,
          rejectsEveryNewField: next.secrets.length > 0 && rejected === next.secrets.length * 3};
      };
      return 'ok';
    }, {id, kit: member.kit, expected: secret});
    const safeCopiedKeyStatus = /^(?:ok|unwrap|keylen|key|value|path|fetch:\d{3}|count:\d+)$/.test(copiedKeyStatus) ? copiedKeyStatus : 'invalid-status';
    testInfo.annotations.push({type: 'safe-phase', description: `copied-key:${safeCopiedKeyStatus}`});
    assert.equal(copiedKeyStatus, 'ok', 'member copies and verifies its authorized old key locally');
    await page.getByRole('button', {name: 'Access', exact: true}).click();
    const access = page.getByRole('dialog', {name: 'Environment access', exact: true});
    const confirmed = page.waitForEvent('dialog').then(async dialog => { assert.equal(dialog.type(), 'confirm'); await dialog.accept(); });
    await access.getByRole('button', {name: 'Remove access', exact: true}).click();
    await confirmed;
    const after = await rotated(stack, id, owner.token, before.key_generation);
    assert.equal(after.membership_version, before.membership_version + 1, 'revocation advances membership once');
    assert.equal((await stack.call('GET', `/api/envs/${id}/e2e/secrets`, member.token)).status, 403, 'removed holder cannot fetch a new key wrap or ciphertext');
    assert.equal((await stack.call('GET', `/api/envs/${id}/e2e/meta`, member.token)).status, 403, 'removed holder cannot fetch a rotation snapshot');
    const replacement = await ciphertext(stack, id, owner.token);
    sameRecordsReencrypted(stored, replacement);
    await currentKeyDecrypts(page, owner, replacement);
    const copied = await memberPage.evaluate(payload => globalThis.clientRekeyCopiedKeyProbe(payload), replacement);
    assert.equal(copied.copiedStillReadable, true, 'revocation cannot erase previously copied ciphertext');
    assert.equal(copied.rejectsEveryNewField, true, 'removed holder old key cannot decrypt replacement ciphertext');
    snapshotRequest(observation, id, before, after.membership_version, owner, member);
    await page.reload();
    await openVault(page, app);
    await unlockVault(page, owner);
    await page.getByRole('button', {name: 'Reveal', exact: true}).click();
    await expect(page.locator('#stable .val')).toHaveText(secret.value);
    assert.equal((await meta(stack, id, owner.token)).key_generation, before.key_generation + 1, 'reload does not rotate an already completed generation again');
    observation.check();
  } finally {
    try { if (checkSecondary) checkSecondary(); }
    finally { await context.close(); }
  }
});

test.describe('pending rotation after an offline holder returns', () => {
  test.use({anonymousBootstraps: 2});
  test('signed-out owner reloads and recovery-kit unlock automatically finishes pending rekey @critical', async ({page, stack}) => {
    const {owner, member, app} = await actorsAndApp(stack, 'pending-client-rekey');
    const observation = watchPlaintext(page, [owner, member]);
    const id = await createVault(page, stack, owner, app);
    await grantMember(page, member);
    const before = await meta(stack, id, owner.token), stored = await ciphertext(stack, id, owner.token);
    const offlineSession = good(await stack.call('POST', '/api/auth/login', '', {email: owner.email, password: owner.password}), 'separate authorized API session');
    const anonymous = () => Promise.all(['/api/instance/edition', '/api/me'].map(path => page.waitForResponse(response =>
      new URL(response.url()).pathname === path && response.request().method() === 'GET' && response.status() === 401)));
    await page.locator('#orgbtn').click();
    const signedOut = anonymous();
    await page.getByRole('menuitem', {name: 'Sign out', exact: true}).click();
    await signedOut;
    await expect(page.locator('#auth')).toBeVisible();
    // The separate API session has no client key. No unlocked browser holder remains to perform re-encryption.
    good(await stack.call('DELETE', `/api/envs/${id}/e2e/grants/${member.id}`, offlineSession.token), 'revoke while browser holder is signed out');
    const pending = await meta(stack, id, offlineSession.token);
    assert.equal(pending.rekey_required, true, 'offline revocation persists pending state');
    assert.equal(pending.key_generation, before.key_generation, 'server cannot rotate without a client key');
    assert.equal(JSON.stringify((await ciphertext(stack, id, offlineSession.token)).secrets), JSON.stringify(stored.secrets), 'pending state alone leaves ciphertext unchanged');
    const reloaded = anonymous();
    await page.reload();
    await reloaded;
    await expect(page.locator('#auth')).toBeVisible();
    await page.getByRole('textbox', {name: 'Email', exact: true}).fill(owner.email);
    await page.locator('#pw').fill(owner.password);
    await page.locator('#authbtn').click();
    await expect(page.locator('#shell')).toBeVisible();
    await openVault(page, app);
    await expect(page.getByRole('button', {name: 'Unlock environment', exact: true})).toBeVisible();
    assert.equal(observation.rekeys.length, 0, 'fresh cookie login does not imply possession of a local recovery key');
    const locked = await meta(stack, id, offlineSession.token);
    assert.equal(locked.rekey_required, true, 'rotation stays pending until the remaining holder unlocks');
    assert.equal(locked.key_generation, before.key_generation, 'locked page cannot advance the key generation');
    await unlockVault(page, owner);
    const after = await rotated(stack, id, offlineSession.token, before.key_generation);
    const replacement = await ciphertext(stack, id, offlineSession.token);
    sameRecordsReencrypted(stored, replacement);
    await currentKeyDecrypts(page, owner, replacement);
    assert.equal((await stack.call('GET', `/api/envs/${id}/e2e/secrets`, member.token)).status, 403, 'removed holder remains unable to fetch a wrap after recovery');
    snapshotRequest(observation, id, before, pending.membership_version, owner, member);
    assert.equal(after.membership_version, pending.membership_version, 'resuming rotation does not invent a membership change');
    await page.getByRole('button', {name: 'Reveal', exact: true}).click();
    await expect(page.locator('#stable .val')).toHaveText(secret.value);
    observation.check();
  });
});
