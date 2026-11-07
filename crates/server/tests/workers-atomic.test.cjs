'use strict';

// Source contracts only. Rollback still needs execution against real DO SQLite.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = path.join(__dirname, '../src');
const db = fs.readFileSync(path.join(src, 'db.rs'), 'utf8');
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
const batchAt = mask(db).search(/\bfn\s+batch\s*\(/);
assert.ok(batchAt >= 0, 'the shared database batch API must exist');
const batch = block(db, batchAt);
function backend(name) {
  const at = mask(batch).search(new RegExp(`Db::${name}\\s*\\(`));
  assert.ok(at >= 0, `${name} batch arm must exist`);
  return block(batch, at);
}
function reachable(source) {
  // Follow Rust helper calls so a safe runtime-binding wrapper is permitted.
  const files = fs.readdirSync(src).filter(name => name.endsWith('.rs'));
  const functions = new Map();
  for (const file of files) {
    const text = fs.readFileSync(path.join(src, file), 'utf8');
    for (const match of mask(text).matchAll(/\bfn\s+(\w+)\s*\(/g)) {
      const candidates = functions.get(match[1]) || [];
      candidates.push(block(text, match.index)); functions.set(match[1], candidates);
    }
  }
  const seen = new Set();
  function visit(text) {
    let out = text;
    for (const call of mask(text).matchAll(/\b(\w+)\s*\(/g)) {
      if (seen.has(call[1]) || !functions.has(call[1])) continue;
      seen.add(call[1]);
      for (const candidate of functions.get(call[1])) out += '\n' + visit(candidate);
    }
    return out;
  }
  return visit(source);
}

test('Workers batch has a real synchronous transaction boundary for rollback on statement failure', () => {
  const worker = backend('DoSqlite');
  const code = mask(reachable(worker));
  assert.ok(/\btransaction_sync\s*\(|\btransactionSync\s*\(/.test(code) ||
    /js_name\s*=\s*"transactionSync"/.test(reachable(worker)),
    'Workers batch must execute through storage.transactionSync (directly or a runtime-binding helper), not a sequential autocommit loop');
  assert.ok(!/\b(?:unwrap_or_default|unwrap_or|is_ok)\s*\(/.test(mask(worker)),
    'Workers batch must not turn statement failure into a successful batch result');
});

test('native batches retain commit and rollback transaction boundaries', () => {
  const sqlite = backend('Sqlite'), postgres = backend('Postgres');
  for (const sql of ['BEGIN IMMEDIATE', 'ROLLBACK', 'COMMIT']) assert.ok(sqlite.includes(`"${sql}"`), `SQLite batch must retain ${sql}`);
  assert.ok(/return\s+Err\s*\(/.test(mask(sqlite)), 'SQLite statement failure must remain an error');
  assert.ok(/\.transaction\s*\(/.test(mask(postgres)) && /\.commit\s*\(/.test(mask(postgres)),
    'PostgreSQL batches must retain a transaction and commit');
  assert.ok(/\.execute\([\s\S]*?\.await[\s\S]*?\?/.test(mask(postgres)), 'PostgreSQL statement failure must propagate before commit');
});
