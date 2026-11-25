// test/app.test.js — the page itself (app.js) driven in node with a minimal DOM stub (no browser, no jsdom):
//  - RPC unreadable (the CORS case) → the status line says so;
//  - framed → refuses to run;
//  - a full click-through against the in-memory chain with an injected UniSat-shaped provider: connect → scan →
//    amount → Build and check → typed confirmation → Sign → node dry run → Broadcast → txid link.
// The DOM stub implements only what app.js touches; a call app.js makes that the stub lacks throws (red).
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { fakeChain, fakeWallet, randTaprootAccount, randTxid } from './helpers.js';

function dom() {
  const els = {};
  const mk = (id) => ({
    id, textContent: '', hidden: false, className: '', value: '', disabled: false, children: [], listeners: {}, href: '',
    addEventListener(t, f) { (this.listeners[t] ||= []).push(f); },
    appendChild(c) { this.children.push(c); },
    fire(t) { for (const f of this.listeners[t] || []) f({}); },
  });
  const document = {
    getElementById: (id) => (els[id] ||= mk(id)),
    createElement: (tag) => mk(tag),
    addEventListener() {},
    body: mk('body'),
  };
  return { document, els };
}

const tick = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(pred, what, ms = 8000) {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await tick(20); }
}
let n = 0;
async function loadApp(win) {
  const { document, els } = dom();
  globalThis.window = win; globalThis.document = document;
  win.top = win; win.self = win;
  await import(`../app.js?run=${++n}`);
  return els;
}

test('RPC unreadable from this origin → the status line names CORS and nothing proceeds', async () => {
  const els = await loadApp({ fetch: async () => { throw new TypeError('Failed to fetch'); } });
  await until(() => /CORS/.test(els['rpc-status'].textContent), 'CORS status');
  assert.equal(els['rpc-status'].className, 'status bad');
  // app.js resolves `window`/`document` at call time: let this instance's delayed wallet scan run against ITS stub
  // before the next test swaps the globals (otherwise its button lands in the next test's page)
  await tick(600);
});

test('framed → refuses to run', async () => {
  const { document } = dom();
  const win = { fetch: async () => { throw new Error('no'); } };
  globalThis.window = win; globalThis.document = document;
  win.top = {}; win.self = win;
  await assert.rejects(import(`../app.js?run=${++n}`), /framed/);
  assert.match(document.body.textContent, /refuses to run inside a frame/);
});

const WASM = process.env.FIRE_IMPL_WASM || `${(await import('node:os')).homedir()}/Documents/fire-migration/alkanes/fire-token_2-77623/impl_4-512_live.wasm`;
const { existsSync, readFileSync } = await import('node:fs');
test('full click-through with an injected single-address wallet against the in-memory chain', {
  skip: existsSync(WASM) ? false : 'the reviewed 4:512 wasm (whose sha256 the page pins) is not on this machine',
}, async () => {
  const holder = randTaprootAccount();
  const FIRE = { block: 2n, tx: 77623n };
  // the fake chain serves the REAL 4:512 bytes, so the page's pinned sha256 check runs unmodified
  const rpc = fakeChain({ bytecode: new Uint8Array(readFileSync(WASM)), coins: [
    { address: holder.address, txid: randTxid(), vout: 0, value: 546n, height: 977000, alkanes: [{ id: FIRE, amount: 250000000n }] },
    { address: holder.address, txid: randTxid(), vout: 1, value: 40000n, height: 977000, alkanes: [] },
  ] });
  const signer = fakeWallet({});
  const unisat = {
    requestAccounts: async () => [holder.address], getPublicKey: async () => holder.publicKey,
    signPsbt: async (hex) => signer.sign({}, Uint8Array.from(Buffer.from(hex, 'hex'))),
  };
  const fetch = async (_url, init) => {
    const req = JSON.parse(init.body);
    const result = await rpc(req.method, req.params);
    return { ok: true, status: 200, text: async () => JSON.stringify({ jsonrpc: '2.0', id: req.id, result }) };
  };
  const els = await loadApp({ fetch, unisat });
  const E = (id) => els[id] || { children: [], textContent: '', hidden: true };
  await until(() => E('wallet-buttons').children.length === 1, 'wallet button');
  assert.equal(els['wallet-buttons'].children[0].textContent, 'Connect UniSat');
  els['wallet-buttons'].children[0].fire('click');
  await until(() => E('fire-balance').textContent === '2.5' || !E('error').hidden, 'FIRE balance', 15000);
  assert.equal(E('error').hidden, true, E('error').textContent);
  assert.ok(els['t-impl'].textContent.startsWith('4:512 · sha256 ac17d1f7'));
  els.feerate.value = '3'; // the stub has no HTML defaults (index.html sets value="3")
  els.amount.value = '0.4'; els.amount.fire('input');
  assert.equal(els['amount-base'].textContent, '40000000');
  els.check.fire('click');
  await until(() => E('summary').textContent.startsWith('burns 0.4 FIRE') || !E('error').hidden, 'review summary', 15000);
  assert.equal(E('error').hidden, true, E('error').textContent);
  assert.match(els.summary.textContent, /returns 2\.1 FIRE to bc1p\S+ · fee \d+ sats/);
  assert.equal(els.sign.disabled, true, 'sign stays disabled until the amount is typed');
  els.confirm.value = '0.40'; els.confirm.fire('input');
  assert.equal(els.sign.disabled, true, 'a different spelling does not unlock signing');
  els.confirm.value = '0.4'; els.confirm.fire('input');
  assert.equal(els.sign.disabled, false);
  els.sign.fire('click');
  // (the stub models no HTML `hidden` attributes, so wait on the status text, not on visibility)
  await until(() => /Nothing has been sent yet/.test(E('send-status').textContent) || !E('error').hidden, 'node dry run', 15000);
  assert.equal(E('error').hidden, true, E('error').textContent);
  assert.match(els['send-status'].textContent, /Nothing has been sent yet/);
  assert.ok(!rpc.state.calls.includes('sendrawtransaction'), 'no broadcast before the second click');
  els.broadcast.fire('click');
  await until(() => E('txid').children.length === 1, 'txid link');
  assert.match(els.txid.children[0].href, /^https:\/\/mempool\.space\/tx\/[0-9a-f]{64}$/);
  assert.equal(rpc.state.calls.filter((c) => c === 'sendrawtransaction').length, 1);
});
