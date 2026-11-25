// test/static.test.js — hardening invariants of the shipped page, checked on the files themselves:
//  - CSP: default-src 'none', scripts/styles 'self' only (no inline, no eval), connect-src = exactly the RPC origin
//    in lib/config.js, Trusted Types required; no third-party <script>/<link>.
//  - SRI values in index.html match app.js / style.css (stale → red).
//  - shipped JS uses no HTML sinks, no eval, no web storage / IndexedDB / cookies, and names no host except the
//    RPC and the explorer link.
//  - repository-wide: no banned HTTP tool, and none of the words the operator asked to be absent (the dropped
//    wallet-file mode). Words are assembled at runtime so this file does not match itself.
// Each scan has a poisoned twin: the same scanner run on a bad string must report it.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, sri } from '../scripts/sri.js';
import { RPC_ORIGIN, RPC_URL, EXPLORER_TX, LOCAL_DEV_ORIGIN, RPC_URL_LOCAL_DEV, rpcUrlFor } from '../lib/config.js';

const read = (f) => readFileSync(join(ROOT, f), 'utf8');
const html = read('index.html');
const shipped = ['app.js', ...readdirSync(join(ROOT, 'lib')).filter((f) => f.endsWith('.js')).map((f) => `lib/${f}`)];
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');

function walk(dir, out = []) {
  for (const f of readdirSync(dir)) {
    if (f === '.git' || f === 'node_modules') continue;
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

function csp(h) {
  const m = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(h);
  assert.ok(m, 'CSP meta present');
  return Object.fromEntries(m[1].split(';').map((d) => d.trim()).filter(Boolean).map((d) => { const [k, ...v] = d.split(/\s+/); return [k, v]; }));
}

function cspProblems(h) {
  const c = csp(h);
  const bad = [];
  if (JSON.stringify(c['default-src']) !== JSON.stringify(["'none'"])) bad.push('default-src');
  if (JSON.stringify(c['script-src']) !== JSON.stringify(["'self'"])) bad.push('script-src');
  if (JSON.stringify(c['style-src']) !== JSON.stringify(["'self'"])) bad.push('style-src');
  if (JSON.stringify(c['connect-src']) !== JSON.stringify([RPC_ORIGIN])) bad.push('connect-src');
  if (!c['require-trusted-types-for']) bad.push('trusted-types');
  if (JSON.stringify(c['trusted-types']) !== JSON.stringify(["'none'"])) bad.push('trusted-types-none');
  if (JSON.stringify(c['object-src']) !== JSON.stringify(["'none'"])) bad.push('object-src');
  if (JSON.stringify(c['base-uri']) !== JSON.stringify(["'none'"])) bad.push('base-uri');
  return bad;
}

test('CSP is strict and its connect-src is exactly the configured RPC origin', () => {
  assert.deepEqual(cspProblems(html), []);
  assert.ok(RPC_URL.startsWith(RPC_ORIGIN + '/'));
  // poisoned twins
  assert.ok(cspProblems(html.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")).includes('script-src'));
  assert.ok(cspProblems(html.replace('connect-src https://mainnet.subfrost.io', 'connect-src https://mainnet.subfrost.io https://evil.example')).includes('connect-src'));
});

const thirdParty = (h) => [...h.matchAll(/<(script|link)[^>]+(src|href)="([^"]+)"/g)].map((m) => m[3]).filter((u) => /^(https?:)?\/\//.test(u));
test('no third-party script or stylesheet; no inline script or style', () => {
  assert.deepEqual(thirdParty(html), []);
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), 'no inline <script>');
  assert.ok(!/<style\b/.test(html) && !/\sstyle="/.test(html), 'no inline style');
  assert.deepEqual(thirdParty('<script src="https://cdn.example/x.js"></script>'), ['https://cdn.example/x.js']); // twin
});

test('SRI values match the shipped files (run `node scripts/sri.js` after editing them)', () => {
  assert.ok(html.includes(`href="style.css" integrity="${sri('style.css')}"`), 'style.css SRI current');
  assert.ok(html.includes(`src="app.js" integrity="${sri('app.js')}"`), 'app.js SRI current');
});

const SINKS = [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/, /document\.write/, /\beval\s*\(/, /new\s+Function\b/,
  /localStorage/, /sessionStorage/, /indexedDB/, /document\.cookie/, /setTimeout\s*\(\s*['"`]/];
const sinkHits = (src) => SINKS.filter((r) => r.test(src)).map(String);
test('shipped JS: no HTML sinks, eval, web storage, IndexedDB or cookies', () => {
  for (const f of shipped) assert.deepEqual(sinkHits(stripComments(read(f))), [], f);
  assert.deepEqual(sinkHits('el.innerHTML = x; localStorage.setItem(1,2)'), [String(SINKS[0]), String(SINKS[6])]); // twin
});

const hosts = (src) => [...stripComments(src).matchAll(/https?:\/\/[^\s'"`)]+/g)].map((m) => m[0]);
test('shipped JS names no host except the RPC and the explorer', () => {
  const allowed = new Set([RPC_URL, RPC_ORIGIN, EXPLORER_TX, LOCAL_DEV_ORIGIN, RPC_URL_LOCAL_DEV]);
  for (const f of shipped) for (const h of hosts(read(f))) assert.ok(allowed.has(h), `${f}: ${h}`);
  assert.deepEqual(hosts("fetch('https://evil.example/x')"), ['https://evil.example/x']); // twin
});

const W = (...p) => p.join('');
const BANNED = [new RegExp(`(^|[^-\\w])${W('cu', 'rl')}\\b`, 'i'), new RegExp(W('wg', 'et'), 'i'),
  new RegExp(W('key', 'store'), 'i'), new RegExp(W('mnem', 'onic'), 'i'), new RegExp(W('pass', 'word'), 'i'), new RegExp(W('pass', 'phrase'), 'i')];
const bannedHits = (s) => BANNED.filter((r) => r.test(s)).map(String);
test('repository: no banned HTTP tool and no trace of the dropped wallet-file mode', () => {
  for (const p of walk(ROOT)) {
    const s = readFileSync(p, 'utf8');
    assert.deepEqual(bannedHits(s), [], p);
  }
  assert.equal(bannedHits(`run ${W('tlsfetch-', 'cu', 'rl')} -s`).length, 0, 'the sanctioned client name is allowed');
  assert.equal(bannedHits(`${W('cu', 'rl')} -s https://x`).length, 1); // twin
  assert.equal(bannedHits(`type your ${W('pass', 'word')}`).length, 1); // twin
});

test('the page refuses to run framed and never writes storage (app.js)', () => {
  const app = read('app.js');
  assert.match(app, /window\.top !== window\.self/);
});

test('local canary mode: only the dev origin gets the allowlisted path, on the same RPC origin', () => {
  assert.ok(RPC_URL_LOCAL_DEV.startsWith(RPC_ORIGIN + '/'));
  assert.equal(rpcUrlFor(LOCAL_DEV_ORIGIN), RPC_URL_LOCAL_DEV);
  for (const o of ['https://0xcasuwu.github.io', 'http://localhost:3001', 'http://127.0.0.1:3000', '']) assert.equal(rpcUrlFor(o), RPC_URL, o); // twins
});
