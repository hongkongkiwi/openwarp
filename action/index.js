'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

function input(name, fallback = '') {
  return process.env[`INPUT_${name.toUpperCase()}`] ?? fallback;
}

function escapeCommand(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

const core = {
  setSecret(value) {
    if (value !== '') process.stdout.write(`::add-mask::${escapeCommand(value)}\n`);
  },
  async setOutput(name, value) {
    if (!process.env.GITHUB_OUTPUT) throw new Error('GITHUB_OUTPUT is required to publish outputs');
    await fs.appendFile(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  },
};

async function main() {
  const required = {};
  for (const name of ['base-url', 'token', 'env-id']) {
    required[name] = input(name).trim();
    if (!required[name]) throw new Error(`Missing required input: ${name}`);
  }
  core.setSecret(required.token);
  const format = input('format', 'dotenv').trim();
  if (!['dotenv', 'json'].includes(format)) throw new Error('Input format must be dotenv or json');
  const mask = input('mask', 'true').trim().toLowerCase();
  if (!['true', 'false'].includes(mask)) throw new Error('Input mask must be true or false');
  const outputFile = input('output-file', '.env');
  if (!outputFile.trim()) throw new Error('Input output-file must not be empty');
  const url = new URL(`${required['base-url'].replace(/\/+$/, '')}/api/envs/${encodeURIComponent(required['env-id'])}/export`);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Input base-url must use HTTP or HTTPS');
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${required.token}` },
    redirect: 'error',
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`OpenWarp export failed: HTTP ${response.status}: ${body}`);
  const data = JSON.parse(body);
  if (!Array.isArray(data.secrets) || typeof data.text !== 'string' ||
      !data.secrets.every(secret => secret && typeof secret.value === 'string')) {
    throw new Error('Invalid OpenWarp export response: expected text and a secrets array with string values');
  }
  if (mask === 'true') {
    for (const secret of data.secrets) core.setSecret(secret.value);
  }
  const destination = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd(), outputFile);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.writeFile(destination, format === 'dotenv' ? data.text : JSON.stringify(data.secrets, null, 2), { mode: 0o600 });
  await fs.chmod(destination, 0o600);
  await core.setOutput('count', data.secrets.length);
}

main().catch(error => {
  process.stdout.write(`::error::${escapeCommand(error.message)}\n`);
  process.exitCode = 1;
});
