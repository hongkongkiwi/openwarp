import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export async function writeWorkerConfig(dir) {
  if ((await fs.readdir(dir)).length) throw new Error('Worker config directory must be empty');
  const source = await fs.readFile(path.join(root, 'wrangler.toml'), 'utf8');
  const main = path.join(root, 'crates/server/build/worker/shim.mjs');
  await fs.access(main);
  let inBuild = false;
  const config = source.split('\n').filter(line => {
    if (/^\s*\[/.test(line)) inBuild = /^\s*\[build\]\s*(?:#.*)?$/.test(line);
    return !inBuild;
  }).join('\n').replace(/^main\s*=.*$/m, `main = ${JSON.stringify(main)}`);
  if (config === source || /^\[build\]/m.test(config)) throw new Error('Could not prepare Worker config');
  const destination = path.join(dir, 'wrangler.toml');
  await fs.writeFile(destination, config, { flag: 'wx' });
  return destination;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await writeWorkerConfig(process.argv[2]);
}
