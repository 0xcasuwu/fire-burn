// test/guards.test.js — every gate in lib/guards.js: a passing case and at least one poisoned twin that fails with
// THAT gate's code (asserted on the code, so an unrelated failure cannot pass for it).
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  GateError, gateAmount, gateDecimals, gateImpl, gateFeeCoins, gateFireCoins, gatePointers, gateOutputs, gateSimulation,
  gateFee, gateTypedConfirmation, gateSignedTx, MAX_FEE_SATS,
} from '../lib/guards.js';
import { planBurn, describeBurnTx, FIRE_ID, FIRE_KEY, REVIEWED_IMPLS, formatUnits, parseUnits } from '../lib/burn.js';
import { encodeCellpack, encipherProtostones, runestoneScript } from '../lib/alkanes.js';
import { addressToScript } from '../lib/address.js';
import { inputMetaFor } from '../lib/wallets.js';
import { randTaprootAccount, randWpkhAccount, randTxid } from './helpers.js';

const code = (c) => (e) => e instanceof GateError && e.code === c;
const OTHER = '2:69805';

function makePlan({ amount = 1000n, fire = [5000n], other = 1n, feeRate = 3 } = {}) {
  const holder = randTaprootAccount(), payer = randWpkhAccount();
  const holderScript = addressToScript(holder.address).script, changeScript = addressToScript(payer.address).script;
  const fireCoins = fire.map((f, i) => {
    const alkanes = new Map([[FIRE_KEY, f]]);
    if (i === 0 && other) alkanes.set(OTHER, other);
    const c = { txid: randTxid(), vout: i, value: 546n, script: holderScript, alkanes, owner: holder };
    return { ...c, meta: inputMetaFor(c, holder) };
  });
  const feeCoins = [{ txid: randTxid(), vout: 1, value: 50000n, script: changeScript, owner: payer }].map((c) => ({ ...c, meta: inputMetaFor(c, payer) }));
  const plan = planBurn({ amount, fireCoins, feeCoins, holderScript, changeScript, feeRate });
  const inputSheets = plan.coins.map((c) => (c.alkanes ? new Map(c.alkanes) : new Map()));
  const prevouts = plan.coins.map((c) => ({ value: c.value, script: c.script }));
  const desc = describeBurnTx(plan.tx, inputSheets, prevouts);
  return { plan, desc, inputSheets, prevouts, holderScript, changeScript, amount };
}

/** Replace the OP_RETURN with a runestone built from `stones` (and runestone pointer) — the tamper tool. */
function retx(m, stones, pointer = 0) {
  const tx = { ...m.plan.tx, outputs: m.plan.tx.outputs.map((o) => ({ ...o })) };
  const n = tx.outputs.length;
  tx.outputs[n - 1] = { value: 0n, script: runestoneScript({ pointer, protocol: encipherProtostones(stones) }) };
  return { tx, desc: describeBurnTx(tx, m.inputSheets, m.prevouts) };
}
const p0 = (o = {}) => ({ protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: 1000n, output: 5 }], message: new Uint8Array(0), ...o });
const p1 = (o = {}) => ({ protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: encodeCellpack(FIRE_ID, [88n]), ...o });

test('gateAmount: passes 0 < N ≤ balance; refuses 0, above balance, non-BigInt', () => {
  gateAmount(1n, 1n);
  assert.throws(() => gateAmount(0n, 10n), code('amount'));
  assert.throws(() => gateAmount(11n, 10n), code('amount'));
  assert.throws(() => gateAmount(1, 10n), code('amount'));
});

test('gateDecimals: 2.1M × 10^8 passes; anything else refuses', () => {
  gateDecimals(210000000000000n);
  assert.throws(() => gateDecimals(2100000000000000n), code('decimals'));
  assert.throws(() => gateDecimals(21000000000000n), code('decimals'));
});

test('gateImpl: reviewed id + sha passes; unknown id, wrong bytes, prototype keys refuse', () => {
  gateImpl({ implId: '4:512', bytecodeSha256: REVIEWED_IMPLS['4:512'] });
  gateImpl({ implId: '4:548', bytecodeSha256: REVIEWED_IMPLS['4:548'] });
  assert.throws(() => gateImpl({ implId: '4:999', bytecodeSha256: REVIEWED_IMPLS['4:512'] }), code('impl'));
  assert.throws(() => gateImpl({ implId: '4:512', bytecodeSha256: REVIEWED_IMPLS['4:548'] }), code('impl'));
  assert.throws(() => gateImpl({ implId: 'toString', bytecodeSha256: 'x' }), code('impl'));
  assert.throws(() => gateImpl({ implId: '__proto__', bytecodeSha256: 'x' }), code('impl'));
});

const H = 977470;
const coin = (o = {}) => ({ txid: randTxid(), vout: 0, value: 20000n, confirmed: true, height: H - 10, ...o });
const opOf = (c) => `${c.txid}:${c.vout}`;
const clean = { indexed: true, inscriptions: [], runes: {} };

test('gateFeeCoins: a verified clean coin passes (and a pre-genesis coin with no indexer row)', () => {
  const a = coin(), b = coin({ height: 870000 });
  gateFeeCoins([a, b], {
    alkanes: new Map([[opOf(a), { empty: false, entries: [] }], [opOf(b), { empty: true, entries: [] }]]),
    ord: new Map([[opOf(a), clean], [opOf(b), clean]]), indexerHeight: H,
  });
});

test('gateFeeCoins poisoned twins: alkanes, no-row after genesis, inscription, runes, ord unindexed/missing, unconfirmed, above indexer', () => {
  const c = coin();
  const base = { alkanes: new Map([[opOf(c), { empty: false, entries: [] }]]), ord: new Map([[opOf(c), clean]]), indexerHeight: H };
  const with_ = (o) => ({ ...base, ...o });
  assert.throws(() => gateFeeCoins([c], with_({ alkanes: new Map([[opOf(c), { empty: false, entries: [{ id: { block: 2n, tx: 0n }, amount: 5n }] }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ alkanes: new Map([[opOf(c), { empty: true, entries: [] }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ alkanes: new Map() })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ ord: new Map([[opOf(c), { ...clean, inscriptions: ['abci0'] }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ ord: new Map([[opOf(c), { ...clean, runes: { X: { amount: 1 } } }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ ord: new Map([[opOf(c), { ...clean, runes: [['X', 1]] }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ ord: new Map([[opOf(c), { ...clean, indexed: false }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ ord: new Map([[opOf(c), { indexed: true, runes: {} }]]) })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([c], with_({ ord: new Map() })), code('fee-coin'));
  assert.throws(() => gateFeeCoins([{ ...c, confirmed: false, height: 0 }], base), code('fee-coin'));
  assert.throws(() => gateFeeCoins([{ ...c, height: H + 1 }], base), code('fee-coin'));
});

test('gateFireCoins: FIRE present + clean ord passes; inscription, no FIRE, no row refuse', () => {
  const c = coin({ value: 546n });
  const fireRead = { empty: false, entries: [{ id: { block: 2n, tx: 77623n }, amount: 9n }] };
  gateFireCoins([c], { alkanes: new Map([[opOf(c), fireRead]]), ord: new Map([[opOf(c), clean]]), indexerHeight: H });
  assert.throws(() => gateFireCoins([c], { alkanes: new Map([[opOf(c), fireRead]]), ord: new Map([[opOf(c), { ...clean, inscriptions: ['i0'] }]]), indexerHeight: H }), code('fire-coin'));
  assert.throws(() => gateFireCoins([c], { alkanes: new Map([[opOf(c), { empty: false, entries: [] }]]), ord: new Map([[opOf(c), clean]]), indexerHeight: H }), code('fire-coin'));
  assert.throws(() => gateFireCoins([c], { alkanes: new Map([[opOf(c), { empty: true, entries: [] }]]), ord: new Map([[opOf(c), clean]]), indexerHeight: H }), code('fire-coin'));
});

test('gatePointers: the built plan passes (partial burn, other alkane returned)', () => {
  const m = makePlan({ amount: 1000n, fire: [5000n, 70n] });
  gatePointers(m.desc, m.plan.tx, m);
  assert.equal(m.desc.burned, 1000n);
});

test('gatePointers poisoned twins: each tampered runestone refuses with code "pointers"', () => {
  const m = makePlan({ amount: 1000n });
  const n = m.plan.tx.outputs.length; // 3 (holder, change, OP_RETURN) → p1 shadow = 5
  assert.equal(n, 3);
  // [stones, runestone pointer, the reason that must fire FIRST (the needle)]
  const cases = {
    'runestone pointer → change': [[p0(), p1()], 1, /runestone pointer/],
    'p0 pointer → change': [[p0({ pointer: 1 }), p1()], 0, /protostone 0 pointer/],
    'p0 refund → OP_RETURN': [[p0({ refund: 2 }), p1()], 0, /protostone 0 refund/],
    'p1 pointer → change': [[p0(), p1({ pointer: 1 })], 0, /protostone 1 pointer/],
    'p1 refund → shadow vout': [[p0(), p1({ refund: 4 })], 0, /protostone 1 refund/],
    'p0 edict amount ≠ N': [[p0({ edicts: [{ id: FIRE_ID, amount: 999n, output: 5 }] }), p1()], 0, /p0 edict amount 999/],
    'p0 edict to change': [[p0({ edicts: [{ id: FIRE_ID, amount: 1000n, output: 1 }] }), p1()], 0, /p0 edict goes to 1/],
    'p0 edict of another alkane': [[p0({ edicts: [{ id: { block: 2n, tx: 69805n }, amount: 1n, output: 5 }] }), p1()], 0, /p0 edict is not FIRE/],
    'p0 two edicts': [[p0({ edicts: [{ id: FIRE_ID, amount: 1000n, output: 5 }, { id: { block: 2n, tx: 69805n }, amount: 1n, output: 1 }] }), p1()], 0, /exactly one edict/],
    'p1 calls op 77': [[p0(), p1({ message: encodeCellpack(FIRE_ID, [77n]) })], 0, /not exactly the FIRE Burn call/],
    'p1 calls another alkane': [[p0(), p1({ message: encodeCellpack({ block: 2n, tx: 77625n }, [88n]) })], 0, /not exactly the FIRE Burn call/],
    'p1 call with an extra argument': [[p0(), p1({ message: encodeCellpack(FIRE_ID, [88n, 1n]) })], 0, /not exactly the FIRE Burn call/],
    'p1 carries an edict': [[p0(), p1({ edicts: [{ id: FIRE_ID, amount: 1n, output: 1 }] })], 0, /p1 must carry no edicts/],
    'three protostones': [[p0(), p1(), p1()], 0, /expected 2 protostones/],
    'p0 carries a call': [[p0({ message: encodeCellpack(FIRE_ID, [99n]) }), p1()], 0, /p0 must carry no call/],
    'protostone burn field': [[p0({ burn: 1 }), p1()], 0, /burn\/from/],
    'protocol tag 2': [[p0({ protocolTag: 2n }), p1()], 0, /not alkanes/],
  };
  for (const [name, [stones, pointer, needle]] of Object.entries(cases)) {
    let r;
    try { r = retx(m, stones, pointer); } catch (e) { assert.fail(`${name}: describe threw ${e.message}`); }
    assert.throws(() => gatePointers(r.desc, r.tx, m), (e) => code('pointers')(e) && needle.test(e.message), name);
  }
});

test('gatePointers backstops, each alone on a synthetic decode: lost alkanes, alkanes on another output, wrong burn, wrong return', () => {
  const m = makePlan({ amount: 1000n });
  const clone = () => ({ ...m.desc, route: { ...m.desc.route, outputs: new Map([...m.desc.route.outputs].map(([k, v]) => [k, new Map(v)])), lost: new Map() } });
  const d1 = clone(); d1.route.lost = new Map([[2, new Map([[OTHER, 1n]])]]);
  assert.throws(() => gatePointers(d1, m.plan.tx, m), (e) => code('pointers')(e) && /lost/.test(e.message));
  const d2 = clone(); d2.route.outputs.set(1, new Map([[OTHER, 1n]]));
  assert.throws(() => gatePointers(d2, m.plan.tx, m), (e) => code('pointers')(e) && /land on output 1/.test(e.message));
  const d3 = clone(); d3.burned = 999n;
  assert.throws(() => gatePointers(d3, m.plan.tx, m), (e) => code('pointers')(e) && /would burn 999/.test(e.message));
  const d4 = clone(); d4.route.outputs.get(0).set(FIRE_KEY, d4.route.outputs.get(0).get(FIRE_KEY) - 1n);
  assert.throws(() => gatePointers(d4, m.plan.tx, m), (e) => code('pointers')(e) && /holder would receive/.test(e.message));
  const d5 = clone(); d5.route.outputs.get(0).set('9:9', 5n);
  assert.throws(() => gatePointers(d5, m.plan.tx, m), (e) => code('pointers')(e) && /9:9: holder would receive 5/.test(e.message));
});

test('gatePointers poisoned twins: holder output replaced by a foreign script; spread edict refused by the decoder', () => {
  const m = makePlan({ amount: 1000n });
  const tx = { ...m.plan.tx, outputs: m.plan.tx.outputs.map((o) => ({ ...o })) };
  tx.outputs[0] = { value: 600n, script: addressToScript(randTaprootAccount().address).script };
  const desc = describeBurnTx(tx, m.inputSheets, m.prevouts);
  assert.throws(() => gatePointers(desc, tx, m), code('pointers'));
  assert.throws(() => retx(m, [p0({ edicts: [{ id: FIRE_ID, amount: 1000n, output: 3 }] }), p1()]), /spreads over every output/);
});

test('gateOutputs: holder + change + OP_RETURN pass; a foreign output or a funded OP_RETURN refuse', () => {
  const m = makePlan();
  gateOutputs(m.plan.tx, m);
  const t1 = { ...m.plan.tx, outputs: m.plan.tx.outputs.map((o, i) => (i === 1 ? { ...o, script: addressToScript(randWpkhAccount().address).script } : o)) };
  assert.throws(() => gateOutputs(t1, m), code('outputs'));
  const t2 = { ...m.plan.tx, outputs: m.plan.tx.outputs.map((o, i, a) => (i === a.length - 1 ? { ...o, value: 1n } : o)) };
  assert.throws(() => gateOutputs(t2, m), code('outputs'));
});

test('gateSimulation: consumed exactly, S accepted, S+1 refused passes; every deviation refuses', () => {
  const ok = { ok: true, returned: [] };
  const good = { amount: 10n, supply: 100n, burnN: ok, burnS: ok, burnS1: { ok: false, error: 'overflow' } };
  gateSimulation(good);
  gateSimulation({ ...good, burnN: { ok: true, returned: [{ id: FIRE_ID, value: 0n }] } }); // a zero entry is nothing
  assert.throws(() => gateSimulation({ ...good, burnN: { ok: false, error: 'x' } }), code('simulation'));
  assert.throws(() => gateSimulation({ ...good, burnN: { ok: true, returned: [{ id: FIRE_ID, value: 5n }] } }), (e) => code('simulation')(e) && /returned FIRE/.test(e.message));
  assert.throws(() => gateSimulation({ ...good, burnN: { ok: true, returned: [{ id: { block: 2n, tx: 0n }, value: 5n }] } }), (e) => code('simulation')(e) && /never given/.test(e.message));
  assert.throws(() => gateSimulation({ ...good, burnS: { ok: false, error: 'x' } }), code('simulation'));
  assert.throws(() => gateSimulation({ ...good, burnS1: ok }), (e) => code('simulation')(e) && /did NOT revert/.test(e.message));
  assert.throws(() => gateSimulation({ ...good, burnS1: { ok: false, error: 'fuel exhausted' } }), (e) => code('simulation')(e) && /another reason/.test(e.message));
  assert.throws(() => gateSimulation({ ...good, amount: 101n }), code('simulation'));
});

test('gateFee: planned fee passes; a mismatch, the ceiling and an absurd rate refuse', () => {
  const m = makePlan();
  gateFee(m.plan, m.desc);
  assert.throws(() => gateFee(m.plan, { ...m.desc, fee: m.desc.fee + 1n }), code('fee'));
  assert.throws(() => gateFee({ ...m.plan, fee: MAX_FEE_SATS + 1n, estVsize: 1_000_000 }, { ...m.desc, fee: MAX_FEE_SATS + 1n }), (e) => code('fee')(e) && /ceiling/.test(e.message));
  assert.throws(() => gateFee({ ...m.plan, fee: 50000n }, { ...m.desc, fee: 50000n }), (e) => code('fee')(e) && /far above/.test(e.message));
  assert.throws(() => gateFee({ ...m.plan, fee: 50000n }, { ...m.desc, fee: 50000n }), code('fee'));
});

test('gateFee liveness: a no-change plan from small FIRE coins at 1 sat/vB (dust dropped into the fee) passes', () => {
  const holder = randTaprootAccount();
  const hs = addressToScript(holder.address).script;
  const fireCoins = [[360n, 50n], [1000n, 60n]].map(([value, f], i) => {
    const c = { txid: randTxid(), vout: i, value, script: hs, alkanes: new Map([[FIRE_KEY, f]]), owner: holder };
    return { ...c, meta: inputMetaFor(c, holder) };
  });
  const plan = planBurn({ amount: 100n, fireCoins, feeCoins: [], holderScript: hs, changeScript: hs, feeRate: 1 });
  assert.equal(plan.tx.outputs.length, 2, 'no change output');
  const desc = describeBurnTx(plan.tx, plan.coins.map((c) => new Map(c.alkanes)), plan.coins.map((c) => ({ value: c.value, script: c.script })));
  gateFee(plan, desc);
  assert.throws(() => gateFee({ ...plan, feeRate: 301 }, desc), (e) => code('fee')(e) && /outside/.test(e.message));
});

test('gateTypedConfirmation: exact formatted amount passes; anything else refuses', () => {
  const n = parseUnits('12.5');
  assert.equal(formatUnits(n), '12.5');
  gateTypedConfirmation('12.5', n);
  gateTypedConfirmation(' 12.5 ', n);
  for (const bad of ['12.50', '12', '125', '', '12,5']) assert.throws(() => gateTypedConfirmation(bad, n), code('confirm'), bad);
});

test('gateSignedTx: same txid + witnesses passes; changed output or missing witness refuses', () => {
  const m = makePlan();
  const der = (last) => new Uint8Array([0x30, ...randomBytes(69), last]);
  const pk = new Uint8Array([0x02, ...randomBytes(32)]);
  const isTr = (k) => m.plan.coins[k].script[0] === 0x51;
  const signedWith = (tr, sw) => ({ ...m.plan.tx, inputs: m.plan.tx.inputs.map((i, k) => ({ ...i, witness: isTr(k) ? tr() : sw() })) });
  const signed = signedWith(() => [new Uint8Array(randomBytes(64))], () => [der(0x01), pk]);
  gateSignedTx(signed, m.plan);
  gateSignedTx(signedWith(() => [new Uint8Array([...randomBytes(64), 0x01])], () => [der(0x01), pk]), m.plan);
  // poisoned twins: a sighash that does not commit to every input and output
  for (const [name, tr, sw] of [
    ['taproot SINGLE|ANYONECANPAY', () => [new Uint8Array([...randomBytes(64), 0x83])], () => [der(0x01), pk]],
    ['taproot NONE', () => [new Uint8Array([...randomBytes(64), 0x02])], () => [der(0x01), pk]],
    ['taproot explicit 0x00 byte', () => [new Uint8Array([...randomBytes(64), 0x00])], () => [der(0x01), pk]],
    ['taproot script-path witness', () => [new Uint8Array(randomBytes(64)), new Uint8Array(randomBytes(34))], () => [der(0x01), pk]],
    ['ecdsa ANYONECANPAY', () => [new Uint8Array(randomBytes(64))], () => [der(0x81), pk]],
    ['ecdsa not DER', () => [new Uint8Array(randomBytes(64))], () => [new Uint8Array(randomBytes(71)).map((x, i, a) => (i === a.length - 1 ? 1 : i === 0 ? 0x31 : x)), pk]],
    ['ecdsa uncompressed key', () => [new Uint8Array(randomBytes(64))], () => [der(0x01), new Uint8Array([0x04, ...randomBytes(64)])]],
  ]) assert.throws(() => gateSignedTx(signedWith(tr, sw), m.plan), code('signed'), name);
  const changed = { ...signed, outputs: signed.outputs.map((o, i) => (i === 1 ? { ...o, value: o.value - 1n } : o)) };
  assert.throws(() => gateSignedTx(changed, m.plan), code('signed'));
  const unsigned = { ...signed, inputs: signed.inputs.map((i, k) => (k === 0 ? { ...i, witness: [] } : i)) };
  assert.throws(() => gateSignedTx(unsigned, m.plan), code('signed'));
});

test('parseUnits / formatUnits: exact, refuse > 8 decimals, signs, exponents', () => {
  assert.equal(parseUnits('131.79173303'), 13179173303n);
  assert.equal(formatUnits(13179173303n), '131.79173303');
  assert.equal(formatUnits(1n), '0.00000001');
  for (const bad of ['1.000000001', '-1', '1e3', '1,5', '.5', ' ', '0x10']) assert.throws(() => parseUnits(bad), /amount/, bad);
});
