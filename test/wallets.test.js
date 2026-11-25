// test/wallets.test.js — each adapter calls its injected provider with the shape subfrost-app uses (lib/wallets.js
// header cites the lines), against fake providers that record the call. This proves the CALL SHAPES, not that a
// real extension signs: that is the operator's canary.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { WALLETS, detectWallets, declaredFeeRateForSubfrost, inputMetaFor, normalizePubkey } from '../lib/wallets.js';
import { addressToScript } from '../lib/address.js';
import { bytesToHex, base64ToBytes } from '../lib/bytes.js';
import { randTaprootAccount, randWpkhAccount, randP2shWpkhAccount } from './helpers.js';

const W = Object.fromEntries(WALLETS.map((w) => [w.id, w]));
const psbt = new Uint8Array(randomBytes(40));
const ctx = (owners) => ({ inputOwners: owners, totalIn: 100000n, totalOut: 98500n, nIn: owners.length, nOut: 3 });

test('detect: each provider is recognised only by its own injection', () => {
  const tr = randTaprootAccount();
  const win = {
    subfrost: Object.freeze({ requestAccounts: async () => [tr.address] }), unisat: {}, oyl: {}, LeatherProvider: {},
    XverseProviders: { BitcoinProvider: {} },
  };
  assert.deepEqual(detectWallets(win).map((w) => w.id).sort(), ['leather', 'oyl', 'subfrost', 'unisat', 'xverse']);
  assert.deepEqual(detectWallets({ subfrost: { requestAccounts: 1 } }).map((w) => w.id), [], 'subfrost needs requestAccounts()');
  assert.deepEqual(detectWallets({}), []);
});

test('SUBFROST: requestAccounts + getPublicKey; signPsbt(hex, {feeRate}) on a FROZEN provider (nothing patched)', async () => {
  const tr = randTaprootAccount();
  const seen = [];
  const p = Object.freeze({
    requestAccounts: async () => [tr.address], getPublicKey: async () => tr.publicKey,
    signPsbt: async (hex, opts) => { seen.push([hex, opts]); return 'aa'; },
  });
  const acc = await W.subfrost.connect(p);
  assert.equal(acc.alkanes.address, tr.address);
  assert.equal(acc.payment.address, tr.address, 'single-address wallet pays fees from the same address');
  await W.subfrost.sign(p, psbt, ctx([tr.address, tr.address]));
  assert.equal(seen[0][0], bytesToHex(psbt));
  const want = Math.floor((1500 / (10 + 68 * 2 + 31 * 3)) * 100) / 100;
  assert.deepEqual(seen[0][1], { feeRate: want });
});

test('SUBFROST declared fee rate mirrors subfrost-app subfrostFeePatch.ts (floor to 0.01, window 1..1000)', () => {
  assert.equal(declaredFeeRateForSubfrost(10000n, 9000n, 1, 2), Math.floor((1000 / (10 + 68 + 62)) * 100) / 100);
  assert.equal(declaredFeeRateForSubfrost(10000n, 9990n, 2, 3), undefined, 'below 1 sat/vB → not declared');
  assert.equal(declaredFeeRateForSubfrost(1n, 2n, 1, 1), undefined, 'outputs above inputs → not declared');
  assert.equal(declaredFeeRateForSubfrost(10n ** 9n, 0n, 1, 1), 1000);
});

test('UniSat: signPsbt(hex, {autoFinalized:true, toSignInputs:[{index,address}]})', async () => {
  const tr = randTaprootAccount();
  let call;
  const p = { requestAccounts: async () => [tr.address], getPublicKey: async () => tr.publicKey, signPsbt: async (...a) => { call = a; return 'bb'; } };
  await W.unisat.connect(p);
  await W.unisat.sign(p, psbt, ctx([tr.address, tr.address]));
  assert.equal(call[0], bytesToHex(psbt));
  assert.deepEqual(call[1], { autoFinalized: true, toSignInputs: [{ index: 0, address: tr.address }, { index: 1, address: tr.address }] });
});

test('OYL: getAddresses → taproot + nativeSegwit; signPsbt({psbt:hex, finalize:false, broadcast:false}) → .psbt', async () => {
  const tr = randTaprootAccount(), sw = randWpkhAccount();
  let call;
  const p = { getAddresses: async () => ({ taproot: tr, nativeSegwit: sw }), signPsbt: async (a) => { call = a; return { psbt: 'cc' }; } };
  const acc = await W.oyl.connect(p);
  assert.equal(acc.alkanes.address, tr.address); assert.equal(acc.payment.address, sw.address);
  assert.equal(await W.oyl.sign(p, psbt, ctx([tr.address])), 'cc');
  assert.deepEqual(call, { psbt: bytesToHex(psbt), finalize: false, broadcast: false });
});

test('Xverse: getAccounts(ordinals,payment); signPsbt {psbt: base64, signInputs: {addr: [i]}, broadcast:false}', async () => {
  const tr = randTaprootAccount(), pay = randP2shWpkhAccount();
  let call;
  const p = {
    request: async (m, a) => {
      if (m === 'getAccounts') return { result: [{ purpose: 'ordinals', ...tr }, { purpose: 'payment', ...pay }] };
      call = [m, a];
      return { result: { psbt: 'ZGQ=' } };
    },
  };
  const acc = await W.xverse.connect(p);
  assert.equal(acc.payment.address, pay.address);
  assert.equal(await W.xverse.sign(p, psbt, ctx([tr.address, pay.address, pay.address])), 'ZGQ=');
  assert.equal(call[0], 'signPsbt');
  assert.deepEqual(base64ToBytes(call[1].psbt), psbt);
  assert.deepEqual(call[1].signInputs, { [tr.address]: [0], [pay.address]: [1, 2] });
  assert.equal(call[1].broadcast, false);
  const bad = { request: async (m) => (m === 'getAccounts' ? { result: [] } : {}) };
  await assert.rejects(W.xverse.connect(bad), /no ordinals/); // poisoned twin
});

test('Leather: getAddresses (BTC p2tr + p2wpkh); signPsbt {hex, signAtIndex, broadcast:false} → result.hex', async () => {
  const tr = randTaprootAccount(), sw = randWpkhAccount();
  let call;
  const p = {
    request: async (m, a) => {
      if (m === 'getAddresses') return { result: { addresses: [{ symbol: 'STX', type: 'p2tr', address: 'x' }, { symbol: 'BTC', type: 'p2tr', ...tr }, { symbol: 'BTC', type: 'p2wpkh', ...sw }] } };
      call = [m, a];
      return { result: { hex: 'ee' } };
    },
  };
  const acc = await W.leather.connect(p);
  assert.equal(acc.alkanes.address, tr.address); assert.equal(acc.payment.address, sw.address);
  assert.equal(await W.leather.sign(p, psbt, ctx([tr.address, sw.address])), 'ee');
  assert.deepEqual(call, ['signPsbt', { hex: bytesToHex(psbt), signAtIndex: [0, 1], broadcast: false }]);
});

test('inputMetaFor: tapInternalKey for p2tr; key must own a p2wpkh / p2sh-p2wpkh coin (poisoned twins: another key)', () => {
  const tr = randTaprootAccount(), sw = randWpkhAccount(), sh = randP2shWpkhAccount(), other = randWpkhAccount();
  const coin = (a) => ({ value: 1000n, script: addressToScript(a.address).script });
  assert.equal(inputMetaFor(coin(tr), tr).tapInternalKey.length, 32);
  assert.equal(inputMetaFor(coin(sw), sw).redeemScript, undefined);
  assert.equal(inputMetaFor(coin(sh), sh).redeemScript.length, 22);
  assert.throws(() => inputMetaFor(coin(sw), { ...sw, publicKey: other.publicKey }), /does not own/);
  assert.throws(() => inputMetaFor(coin(sh), { ...sh, publicKey: other.publicKey }), /not a p2sh-p2wpkh/);
  assert.throws(() => normalizePubkey('04' + '11'.repeat(64)), /unexpected public key length/);
  assert.equal(normalizePubkey('11'.repeat(32)).xonly.length, 32);
});

test('SUBFROST poisoned twin: a fee the extension would patch is refused BEFORE the popup', async () => {
  const tr = randTaprootAccount();
  let called = false;
  const p = Object.freeze({ signPsbt: async () => { called = true; return 'aa'; } });
  await assert.rejects(W.subfrost.sign(p, psbt, { inputOwners: Array(6).fill(tr.address), totalIn: 10490n, totalOut: 10000n, nIn: 6, nOut: 3 }), /fee rate too low/);
  assert.equal(called, false);
});
