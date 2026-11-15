const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../src/app.rs'), 'utf8');
const handler = name => {
  const start = source.indexOf(`async fn ${name}(`);
  assert.notEqual(start, -1);
  const end = source.indexOf('\nasync fn ', start + 1);
  return source.slice(start, end < 0 ? undefined : end);
};

test('rotation owns the credential gate before the key and metadata snapshots, including detached blocking work', () => {
  const body = handler('rotate_master');
  const gate = body.indexOf('let credential_guard = st.secret_health_credentials.clone().lock_owned().await;');
  assert.ok(gate >= 0, 'rotation must acquire the shared credential gate');
  assert.ok(gate < body.indexOf('let old = st.master()'), 'gate must precede the master snapshot');
  const preflight = body.indexOf('verify_master(&st.db, &old)');
  assert.ok(preflight > gate, 'gate must precede verification of persisted credentials');
  const inventory = source.match(/const MASTER_STORES:[^]*?\n\];/);
  assert.ok(inventory, 'rotation must have an encrypted-store inventory');
  const metadata = inventory[0].match(/MasterStore \{ table: "meta",[^\n]+/);
  assert.ok(metadata, 'the inventory must include encrypted metadata');
  for (const prefix of ['hibp_api_key:', 'enzoic_credentials:']) assert.ok(metadata[0].includes(prefix), `${prefix} must be included in the gated inventory`);
  assert.match(source, /fn select\(&self\) -> String \{ format!\("SELECT \* FROM \{\} WHERE \{\}",self\.table,self\.predicate\) \}/);
  assert.match(handler('verify_master'), /master_updates\(db, key, key\)\.await\?/);
  assert.match(handler('master_updates'), /for store in MASTER_STORES \{[^\n]*db\.query\(&store\.select\(\),&\[\]\)\.await\?/);
  const blocking = body.indexOf('tokio::task::spawn_blocking(move || {');
  assert.ok(blocking > gate, 'gate must precede the detached inventory snapshot');
  const transaction = body.indexOf('st2.db.webhook_atomic(move |tx| {', blocking);
  const snapshot = body.indexOf('let rows=tx.query(&store.select(),&[])?;', transaction);
  assert.ok(transaction > blocking && snapshot > transaction, 'the inventory must be snapshotted inside the atomic rotation');
  assert.match(body.slice(transaction, snapshot), /for store in MASTER_STORES \{/);
  const owned = body.indexOf('let _credential_guard = credential_guard;', blocking);
  assert.ok(owned > blocking && owned < snapshot && owned < body.indexOf('st2.master.write()', blocking), 'blocking task must own the guard even if the request is cancelled');
});

test('credential writes, deletes and read/decrypt snapshots share the rotation gate', () => {
  for (const name of ['secret_health_settings', 'secret_health_save', 'enzoic_settings', 'enzoic_save']) {
    const body = handler(name);
    const gate = body.indexOf('let _credential_guard = st.secret_health_credentials.lock().await;');
    // DB access may be inline (`st.db.`) or factored into the guarded helpers.
    const access = ['st.db.', 'secret_health_revalidate', 'secret_health_store', 'secret_health_delete']
      .map(token => body.indexOf(token)).filter(index => index >= 0);
    assert.ok(gate >= 0 && access.length > 0 && access.every(index => gate < index), `${name} must gate its complete database operation`);
  }
  for (const name of ['secret_health_email', 'enzoic_password']) {
    const body = handler(name);
    const gate = body.indexOf('let credential_guard = st.secret_health_credentials.lock().await;');
    assert.ok(gate >= 0 && gate < body.indexOf('let row = st.db.'), `${name} must gate the ciphertext snapshot`);
    const release = body.indexOf('drop(credential_guard);');
    assert.ok(release > body.indexOf('oc::decrypt_symmetric') && release < body.indexOf('let quota ='), `${name} must release after decryption and before egress`);
  }
});
