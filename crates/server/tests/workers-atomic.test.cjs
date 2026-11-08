'use strict';

// Source contracts only. Rollback still needs execution against real DO SQLite.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const db = fs.readFileSync(path.join(__dirname, '../src/db.rs'), 'utf8');
function mask(source) {
  return source.replace(/r(#{0,16})"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    value => value.replace(/[^\n]/g, ' '));
}
function block(source, start) {
  const code = mask(source), open = code.indexOf('{', start);
  assert.ok(open >= 0, 'source contract requires a Rust block');
  let depth = 1, end = open;
  while (++end < code.length && depth) {
    if (code[end] === '{') depth++;
    if (code[end] === '}') depth--;
  }
  assert.equal(depth, 0, 'Rust block must be balanced');
  return source.slice(open + 1, end - 1);
}
function body(source, name) {
  const matches = [...mask(source).matchAll(new RegExp(`\\bfn\\s+${name}\\s*\\(`, 'g'))];
  assert.equal(matches.length, 1, `${name} must have one unambiguous implementation`);
  return block(source, matches[0].index);
}
function batchBody(source) {
  const batch = body(source, 'batch');
  if (/\bDb::\w+\s*\(/.test(mask(batch))) return batch;
  assert.match(mask(batch), /^\s*(?:return\s+)?self\.batch_checked\(statements,\s*&\[\]\)\.await\s*;?\s*$/,
    'batch must return the checked helper result without executing autocommit writes');
  return body(source, 'batch_checked');
}
function backend(source, name) {
  const batch = batchBody(source);
  const at = mask(batch).search(new RegExp(`Db::${name}\\s*\\(`));
  assert.ok(at >= 0, `${name} batch arm must exist`);
  return block(batch, at);
}
function nativeContract(source, name) {
  const arm = backend(source, name), code = mask(arm);
  const shared = mask(batchBody(source));
  assert.match(shared, /if\s+require_one\.contains\(&index\)\s*&&\s*rows\s*!=\s*1\s*\{\s*Err\s*\(/,
    'required native statements must reject every affected-row count except one');
  assert.ok(!/\b(?:unwrap_or_default|unwrap_or|is_ok)\s*\(/.test(code), 'batch failures must not become success');
  const loopAt = code.search(/for\s*\(index,\s*\(sql,\s*params\)\)\s+in\s+statements\.iter\(\)\.enumerate\(\)/);
  assert.ok(loopAt >= 0, `${name} must execute and check each statement`);
  const loop = mask(block(arm, loopAt));
  assert.ok(code.indexOf('tx.commit(') > loopAt, `${name} must commit only after the statement loop`);
  if (name === 'Sqlite') {
    assert.match(code.slice(0, loopAt), /let\s+tx\s*=\s*conn\.transaction_with_behavior\(rusqlite::TransactionBehavior::Immediate\)[\s\S]*?\?/,
      'SQLite must open an immediate rusqlite transaction before executing statements');
    assert.match(loop, /checked\(index,\s*exec_sqlite\(&tx,\s*sql,\s*params\)\?\)\?/,
      'SQLite statement and exact-one errors must exit before commit, dropping the transaction for rollback');
    assert.ok(!/set_drop_behavior|DropBehavior::Commit|mem::forget/.test(code), 'SQLite must retain rollback-on-drop semantics');
    assert.match(code, /tx\.commit\(\)\.map_err\(/, 'SQLite commit failure must propagate');
  } else if (name === 'Postgres') {
    assert.match(code.slice(0, loopAt), /let\s+tx\s*=\s*client\.transaction\(\)\.await[\s\S]*?\?/,
      'PostgreSQL must open a transaction before executing statements');
    assert.match(loop, /checked\(index,\s*tx\.execute\([\s\S]*?\.await\.map_err\(pg_err\)\?\)\?/,
      'PostgreSQL execution and exact-one errors must propagate from the transaction');
    assert.match(code, /tx\.commit\(\)\.await\.map_err\(pg_err\)/, 'PostgreSQL commit failure must propagate');
    assert.match(arm, /if\s+result\.is_err\(\)\s*\{\s*let\s+_\s*=\s*client\.batch_execute\("ROLLBACK"\)\.await;/,
      'PostgreSQL must clean up a failed transaction');
    assert.match(code, /\bresult\s*$/, 'PostgreSQL must return the transaction result');
  } else {
    assert.match(code.slice(0, loopAt), /let\s+mut\s+tx\s*=\s*client\.start_transaction\([\s\S]*?\.await[\s\S]*?\?/,
      'MySQL must open a transaction before executing statements');
    assert.match(loop, /tx\.exec_drop\([\s\S]*?\.await\.map_err\([\s\S]*?\?;/, 'MySQL execution errors must propagate');
    assert.match(loop, /checked\(index,\s*tx\.affected_rows\(\)\)/, 'MySQL must check the transaction affected-row count');
    assert.match(loop, /if\s+let\s+Err\(e\)\s*=\s*result\s*\{[\s\S]*?tx\.rollback\(\)\.await;\s*return\s+Err\(e\)/,
      'MySQL must roll back and return statement or exact-one errors');
    assert.match(code, /tx\.commit\(\)\.await\.map_err\(/, 'MySQL commit failure must propagate');
    assert.match(arm, /if\s+result\.is_err\(\)\s*\{\s*let\s+_\s*=\s*client\.query_drop\("ROLLBACK"\)\.await;/,
      'MySQL must clean up a failed commit');
    assert.match(code, /\bresult\s*$/, 'MySQL must return the transaction result');
  }
}
function workerContract(source) {
  assert.match(mask(backend(source, 'DoSqlite')), /^\s*s\.transaction_sync\(statements,\s*require_one\)\s*$/,
    'Workers must return the synchronous transaction helper result with exact-one guards');
  const helper = body(source, 'transaction_sync'), code = mask(helper);
  assert.match(code, /self\.storage\.as_ref\(\)\.ok_or\([\s\S]*?\)\?/,
    'Workers must fail closed without transactional Durable Object storage');
  assert.match(helper, /let\s+transaction\s*=\s*js_sys::Reflect::get\(raw,\s*&JsValue::from_str\("transactionSync"\)\)/,
    'Workers must resolve the real storage.transactionSync runtime binding');
  assert.match(code, /\.dyn_into::<js_sys::Function>\(\)\.map_err\([\s\S]*?\)\?/,
    'Workers must reject a missing or invalid runtime transaction function');
  const callbackAt = code.indexOf('Closure::wrap(');
  assert.ok(callbackAt >= 0, 'Workers must provide a synchronous transaction callback');
  const callback = block(helper, callbackAt), callbackCode = mask(callback);
  assert.ok(!/\basync\b|\.await\b/.test(callbackCode), 'transactionSync callback must not yield');
  assert.match(callbackCode, /sql\.exec\(statement,\s*do_binds\(params\)\)\.map_err\([\s\S]*?\?;/,
    'Workers statement failures must throw out of the transaction callback');
  assert.match(callbackCode, /for\s+row\s+in\s+cursor\.raw\(\)\s*\{\s*row\.map_err\([\s\S]*?\?;/,
    'Workers must consume cursor results and propagate deferred statement failures');
  const guardAt = callbackCode.search(/if\s+require_one\.contains\(&index\)/);
  assert.ok(guardAt >= 0, 'Workers must enforce required statement row counts inside the callback');
  const guard = block(callback, guardAt);
  assert.match(guard, /sql\.exec\("SELECT changes\(\) AS affected",\s*None\)/,
    'Workers exact-one checks must use affected table rows, not index writes');
  assert.match(guard, /if\s+changes\["affected"\]\.as_u64\(\)\s*!=\s*Some\(1\)\s*\{\s*return\s+Err\(/,
    'Workers must throw for zero or multiple affected rows');
  assert.match(code, /transaction\.call1\(raw,\s*callback\.as_ref\(\)\)\.map_err\([\s\S]*?\?;/,
    'Workers must invoke transactionSync with the callback and propagate rollback errors');
  assert.ok(!/\b(?:unwrap_or_default|unwrap_or|is_ok)\s*\(/.test(code), 'Workers must not swallow transaction or statement failure');
  assert.ok(!/\bsql\.exec\s*\(/.test(mask(helper.replace(callback, ''))),
    'Workers batch writes must occur only inside the transaction callback');
}

test('Workers batch has a real synchronous transaction boundary for rollback on statement failure', () => {
  workerContract(db);
});

for (const name of ['Sqlite', 'Postgres', 'Mysql']) {
  test(`${name} batches retain commit, rollback and exact-one transaction guards`, () => {
    nativeContract(db, name);
  });
}

function fixture(before, after) {
  assert.equal(db.split(before).length, 2, 'negative fixture must change one source site');
  return db.replace(before, after);
}

test('batch parser follows only a returned checked helper, not comments or autocommit writes', () => {
  const checked = 'fn batch_checked() { match self { Db::Sqlite(c) => { safe(); } } }';
  const source = `fn batch() { self.batch_checked(statements, &[]).await } ${checked}`;
  assert.match(backend(source, 'Sqlite'), /safe\(\)/);
  assert.throws(() => backend(`fn batch() { /* self.batch_checked(statements, &[]).await */ Ok(()) } ${checked}`, 'Sqlite'),
    /batch must return the checked helper result/);
  assert.throws(() => backend(`fn batch() { self.exec(sql, params).await?; self.batch_checked(statements, &[]).await } ${checked}`, 'Sqlite'),
    /batch must return the checked helper result/);
});

test('native source contracts reject autocommit statements and weakened exact-one guards', () => {
  for (const [name, before, after, reason] of [
    ['Sqlite', 'exec_sqlite(&tx, sql, params)?', 'exec_sqlite(&conn, sql, params)?', /SQLite statement and exact-one errors/],
    ['Postgres', 'checked(index, tx.execute', 'checked(index, client.execute', /PostgreSQL execution and exact-one errors/],
    ['Mysql', 'tx.exec_drop(sql2.as_str()', 'client.exec_drop(sql2.as_str()', /MySQL execution errors/],
  ]) assert.throws(() => nativeContract(fixture(before, after), name), reason, `${name} autocommit must be rejected`);
  for (const name of ['Sqlite', 'Postgres', 'Mysql']) {
    assert.throws(() => nativeContract(fixture('rows != 1', 'rows > 1'), name), /required native statements must reject/);
  }
  assert.throws(() => nativeContract(fixture('checked(index, exec_sqlite(&tx, sql, params)?)?;',
    'let _ = checked(index, exec_sqlite(&tx, sql, params)?);'), 'Sqlite'), /SQLite statement and exact-one errors/);
});

test('Workers source contract rejects fake transactions, autocommit writes and weakened row guards', () => {
  for (const [before, after, reason] of [
    ['s.transaction_sync(statements, require_one)', 's.exec(statements, require_one)', /Workers must return the synchronous transaction helper/],
    ['"transactionSync"', '"notATransaction"', /Workers must resolve the real storage.transactionSync/],
    ['transaction.call1(raw, callback.as_ref())', 'callback.call0(raw)', /Workers must invoke transactionSync/],
    ['let callback = worker::wasm_bindgen::closure::Closure::wrap', 'sql.exec(statement, do_binds(params))?; let callback = worker::wasm_bindgen::closure::Closure::wrap', /Workers batch writes must occur only inside/],
    ['changes["affected"].as_u64() != Some(1)', 'changes["affected"].as_u64() > Some(1)', /Workers must throw for zero or multiple/],
    ['for row in cursor.raw() { row.map_err(|e| JsValue::from_str(&e.to_string()))?; }',
      'for row in cursor.raw() { let _ = row; }', /Workers must consume cursor results/],
  ]) assert.throws(() => workerContract(fixture(before, after)), reason);
});
