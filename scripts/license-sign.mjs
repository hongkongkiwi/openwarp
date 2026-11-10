#!/usr/bin/env node
// Issue an OpenWarp enterprise license. The token is signed offline with the
// vendor P-256 key and verified by the server with the embedded public key.
//
// Usage:
//   node scripts/license-sign.mjs --customer "Acme Ltd" [--days 365] [--private-key PATH]
//
// The private key defaults to $OPENWARP_LICENSE_PRIVATE_KEY or
// ~/.openwarp/enterprise-signing-key.pem. Never commit it. The token goes to
// stdout; diagnostics go to stderr so it can be captured directly.
'use strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function arg(name, fallback = '') {
  const at = process.argv.indexOf('--' + name);
  return at >= 0 && process.argv[at + 1] ? process.argv[at + 1] : fallback;
}

const customer = arg('customer').trim();
const days = Number(arg('days', '365'));
const keyPath = arg('private-key', process.env.OPENWARP_LICENSE_PRIVATE_KEY || path.join(os.homedir(), '.openwarp', 'enterprise-signing-key.pem'));
if (!customer) { console.error('usage: license-sign.mjs --customer "Acme Ltd" [--days 365] [--private-key PATH]'); process.exit(2); }
if (!Number.isFinite(days) || days < 1 || days > 3650) { console.error('--days must be between 1 and 3650'); process.exit(2); }
if (!fs.existsSync(keyPath)) { console.error('signing key not found: ' + keyPath); process.exit(2); }

const now = Math.floor(Date.now() / 1000);
const header = { alg: 'ES256', typ: 'JWT', kid: 'ow-2026-01' };
const claims = { v: 1, iss: 'openwarp', sub: 'enterprise', customer, iat: now, exp: now + Math.floor(days * 86400) };
const b64 = value => Buffer.from(value).toString('base64url');
const data = b64(JSON.stringify(header)) + '.' + b64(JSON.stringify(claims));
const signature = crypto.sign('sha256', Buffer.from(data), { key: fs.readFileSync(keyPath), dsaEncoding: 'ieee-p1363' });
process.stderr.write(`enterprise license for ${customer}, expires ${new Date(claims.exp * 1000).toISOString()}\n`);
process.stdout.write(data + '.' + signature.toString('base64url') + '\n');
