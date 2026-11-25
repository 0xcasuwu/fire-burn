// scripts/tlsfetch-transport.js — node-side RPC transport for the read-only scripts: spawns `tlsfetch-curl`
// (the HTTP client these scripts use) with the JSON body on stdin.
// Never used by the page (the page uses the browser's fetch).
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { execFileSync } from 'node:child_process';

export function tlsfetchTransport(bin = 'tlsfetch-curl') {
  return async (url, body) => execFileSync(bin, ['-s', '--max-time', '60', '-X', 'POST', url,
    '-H', 'Content-Type: application/json', '--data-binary', '@-'], { input: body, encoding: 'utf8', maxBuffer: 64 << 20 });
}
