// scripts/sri.js — write sha384 Subresource Integrity values for app.js and style.css into index.html.
// Run after editing either file:  node scripts/sri.js     (test/static.test.js fails while they are stale)
// lib/*.js are imported as same-origin ES modules; SRI covers the entry points (no third-party or vendored asset
// exists in this repo).
// JOURNAL 2026-11-25 created for fire-burn.

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const sri = (file) => 'sha384-' + createHash('sha384').update(readFileSync(join(ROOT, file))).digest('base64');

export function withSri(html) {
  return html
    .replace(/(<link rel="stylesheet" href="style\.css" integrity=")[^"]*(")/, `$1${sri('style.css')}$2`)
    .replace(/(<script type="module" src="app\.js" integrity=")[^"]*(")/, `$1${sri('app.js')}$2`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const p = join(ROOT, 'index.html');
  const before = readFileSync(p, 'utf8');
  const after = withSri(before);
  writeFileSync(p, after);
  console.log(before === after ? 'index.html SRI already current' : 'index.html SRI updated');
}
