// test/flow.test.js — the whole burn path (lib/flow.js) against the in-memory chain and fake wallets: read →
// scan → verify fee coins → preflight (plan, decode, gates, simulation) → typed confirmation → sign → signed-tx
// gate → mempool dry run → broadcast. Poisoned twins for every live-state gate and for hostile wallets.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFire, loadCoins, scanFireCoins, verifyFeeCoins, preflight, signAndCheck, mempoolCheck, broadcast } from '../lib/flow.js';
import { GateError } from '../lib/guards.js';
import { FIRE_KEY, formatUnits } from '../lib/burn.js';
import { ordOutputs } from '../lib/chain.js';
import { parseTx } from '../lib/tx.js';
import { hexToBytes } from '../lib/bytes.js';
import { addressToScript } from '../lib/address.js';
import { fakeChain, fakeWallet, randTaprootAccount, randWpkhAccount, randP2shWpkhAccount, randTxid } from './helpers.js';

const code = (c) => (e) => e instanceof GateError && e.code === c;
const FIRE = { block: 2n, tx: 77623n };
const OTHER = { block: 2n, tx: 69805n };
const H = 977470;

function world({ payer = randWpkhAccount(), feeCoins, fireCoins, ...chainOpts } = {}) {
  const holder = randTaprootAccount();
  const accounts = { alkanes: { ...holder, ...addressToScript(holder.address) }, payment: { ...payer, ...addressToScript(payer.address) } };
  const coins = [
    ...(fireCoins || [
      { address: holder.address, txid: randTxid(), vout: 0, value: 546n, height: H - 100, alkanes: [{ id: FIRE, amount: 13000000000n }, { id: OTHER, amount: 1n }] },
      { address: holder.address, txid: randTxid(), vout: 1, value: 600n, height: H - 50, alkanes: [{ id: FIRE, amount: 179173303n }] },
      { address: holder.address, txid: randTxid(), vout: 2, value: 546n, height: H - 40, alkanes: [] },
    ]).map((c) => ({ address: holder.address, ...c })),
    ...(feeCoins || [
      { address: payer.address, txid: randTxid(), vout: 0, value: 80000n, height: H - 5, alkanes: [] },
      { address: payer.address, txid: randTxid(), vout: 3, value: 5000n, height: H - 5, alkanes: [] },
    ]).map((c) => ({ address: payer.address, ...c })),
  ];
  const rpc = fakeChain({ coins, ...chainOpts });
  return { rpc, accounts, reviewed: { '4:512': rpc.bytecodeSha }, coins };
}

async function runToPreflight(w, amount, feeRate = 3) {
  const st = await readFire(w.rpc, { reviewed: w.reviewed });
  const coins = await loadCoins(w.rpc, w.accounts, st.height);
  const scan = await scanFireCoins(w.rpc, coins, w.accounts, st.tag);
  const ordFire = await ordOutputs(w.rpc, scan.fireCoins.map((c) => c.op));
  const fee = await verifyFeeCoins(w.rpc, coins.filter((c) => !scan.fireCoins.some((f) => f.op === c.op)), w.accounts, st.tag, st.height, 20000n);
  const pre = await preflight(w.rpc, st, {
    amount, feeRate, accounts: w.accounts, fireCoins: scan.fireCoins, feeCoins: fee.clean,
    ordFire, ordFee: fee.ord, alkanesReads: new Map([...scan.reads, ...fee.alkanes]),
  });
  return { st, coins, scan, fee, pre };
}

test('end to end: partial burn of 1.5 FIRE — summary, decode, sign, dry run, broadcast', async () => {
  const w = world();
  const amount = 150000000n;
  const { st, scan, pre } = await runToPreflight(w, amount);
  assert.equal(st.implId, '4:512');
  assert.equal(scan.fireCoins.length, 2);
  assert.equal(pre.desc.burned, amount);
  assert.equal(pre.plan.fireCoinsUsed, 1, 'largest FIRE coin alone covers 1.5 FIRE');
  assert.equal(pre.holderGets.get(FIRE_KEY), 13000000000n - amount);
  assert.equal(pre.holderGets.get('2:69805'), 1n, 'the other alkane on the FIRE coin comes back');
  assert.match(pre.summary, /^burns 1\.5 FIRE · returns 128\.5 FIRE \+ 1 other alkane to bc1p\S+ · fee \d+ sats$/);
  const wallet = fakeWallet(w.accounts);
  const s = await signAndCheck(w.rpc, wallet, {}, pre, formatUnits(amount), st);
  await mempoolCheck(w.rpc, s.hex, pre.plan);
  const id = await broadcast(w.rpc, s.hex, pre.plan, st);
  assert.equal(id, pre.plan.txid);
  const sent = parseTx(hexToBytes(s.hex));
  assert.ok(sent.inputs.every((i) => i.witness.length > 0));
});

test('end to end with an Xverse-style p2sh-p2wpkh payment account (redeemScript written)', async () => {
  const w = world({ payer: randP2shWpkhAccount() });
  const { st, pre } = await runToPreflight(w, 1n);
  const feeIdx = pre.plan.fireCoinsUsed;
  assert.ok(pre.plan.coins[feeIdx].meta.redeemScript, 'p2sh fee input carries its redeemScript');
  const s = await signAndCheck(w.rpc, fakeWallet(w.accounts), {}, pre, formatUnits(1n), st);
  const sent = parseTx(hexToBytes(s.hex));
  assert.equal(sent.inputs[feeIdx].scriptSig.length, 23, 'scriptSig = push(0x0014‖hash160)');
});

test('burning the whole balance spends both FIRE coins and returns 0 FIRE (other alkane still returned)', async () => {
  const w = world();
  const all = 13000000000n + 179173303n;
  const { st, pre } = await runToPreflight(w, all);
  assert.equal(pre.plan.fireCoinsUsed, 2);
  assert.equal(pre.holderGets.get(FIRE_KEY), undefined);
  assert.equal(pre.holderGets.get('2:69805'), 1n);
});

test('poisoned twins — live state: unreviewed impl, tampered bytes, wrong name, wrong max supply', async () => {
  await assert.rejects(readFire(world({ impl: { block: 4n, tx: 999n } }).rpc, { reviewed: {} }), code('impl'));
  const w = world();
  await assert.rejects(readFire(w.rpc, { reviewed: { '4:512': 'ab'.repeat(32) } }), code('impl'));
  const w2 = world({ name: 'FIRE2' });
  await assert.rejects(readFire(w2.rpc, { reviewed: w2.reviewed }), code('identity'));
  const w3 = world({ maxSupply: 21n });
  await assert.rejects(readFire(w3.rpc, { reviewed: w3.reviewed }), code('decimals'));
});

test('poisoned twins — a contract that burns half, or never underflows, fails the simulation gate', async () => {
  await assert.rejects(runToPreflight(world({ burnBehaviour: 'half' }), 100n), code('simulation'));
  await assert.rejects(runToPreflight(world({ burnBehaviour: 'no-underflow' }), 100n), code('simulation'));
});

test('poisoned twins — fee coins: alkanes / inscription / no-row are skipped, never spent; nothing clean → refuse', async () => {
  const bad = [
    { txid: randTxid(), vout: 0, value: 90000n, height: H - 5, alkanes: [{ id: { block: 2n, tx: 0n }, amount: 7n }] },
    { txid: randTxid(), vout: 1, value: 70000n, height: H - 5, alkanes: [], ord: { indexed: true, inscriptions: ['x'], runes: {} } },
    { txid: randTxid(), vout: 2, value: 60000n, height: H - 5, alkanes: 'empty' },
  ];
  const w = world({ feeCoins: [...bad, { txid: randTxid(), vout: 9, value: 40000n, height: H - 5, alkanes: [] }] });
  const st = await readFire(w.rpc, { reviewed: w.reviewed });
  const coins = await loadCoins(w.rpc, w.accounts, st.height);
  const fee = await verifyFeeCoins(w.rpc, coins.filter((c) => c.value > 1000n), w.accounts, st.tag, st.height, 1_000_000n);
  assert.equal(fee.rejected.length, 3);
  assert.equal(fee.clean.length, 1);
  assert.ok(fee.rejected.every((r) => /fee-coin/.test(r.why)));
  // only dirty coins → the plan cannot be paid
  const w2 = world({ feeCoins: bad });
  await assert.rejects(runToPreflight(w2, 1n), /not enough clean BTC/);
});

test('poisoned twin — ord unreachable: no fee coin is picked', async () => {
  const w = world({ ordDown: true });
  const st = await readFire(w.rpc, { reviewed: w.reviewed });
  const coins = await loadCoins(w.rpc, w.accounts, st.height);
  await assert.rejects(verifyFeeCoins(w.rpc, coins.filter((c) => c.value > 1000n), w.accounts, st.tag, st.height, 1000n), code('fee-coin'));
});

test('poisoned twins — FIRE coin unconfirmed or above the indexer is not scanned', async () => {
  const holderCoins = [
    { txid: randTxid(), vout: 0, value: 546n, height: 0, alkanes: [{ id: FIRE, amount: 5n }] },
    { txid: randTxid(), vout: 1, value: 546n, height: H + 1, alkanes: [{ id: FIRE, amount: 5n }] },
  ];
  const w = world({ fireCoins: holderCoins });
  const st = await readFire(w.rpc, { reviewed: w.reviewed });
  const coins = await loadCoins(w.rpc, w.accounts, st.height);
  const scan = await scanFireCoins(w.rpc, coins, w.accounts, st.tag);
  assert.equal(scan.total, 0);
  assert.equal(scan.fireCoins.length, 0);
});

test('poisoned twins — amount 0 / above balance refused before any plan', async () => {
  await assert.rejects(runToPreflight(world(), 0n), code('amount'));
  await assert.rejects(runToPreflight(world(), 13179173304n), code('amount'));
});

test('poisoned twins — wallet rewrites the fee, returns unsigned inputs, or the user mistypes', async () => {
  const w = world();
  const { st, pre } = await runToPreflight(w, 1000n);
  await assert.rejects(signAndCheck(w.rpc, fakeWallet(w.accounts, { tamper: 'fee' }), {}, pre, formatUnits(1000n), st), code('signed'));
  await assert.rejects(signAndCheck(w.rpc, fakeWallet(w.accounts, { tamper: 'unsigned' }), {}, pre, formatUnits(1000n), st), /not signed/);
  await assert.rejects(signAndCheck(w.rpc, fakeWallet(w.accounts), {}, pre, '0.0001', st), code('confirm')); // shown amount is 0.00001
  await assert.rejects(signAndCheck(w.rpc, fakeWallet(w.accounts, { tamper: 'anyonecanpay' }), {}, pre, formatUnits(1000n), st), code('signed'));
});

test('poisoned twin — FIRE repointed to another implementation after the check: no wallet prompt, no broadcast', async () => {
  const w = world();
  const { st, pre } = await runToPreflight(w, 1000n);
  const s = await signAndCheck(w.rpc, fakeWallet(w.accounts), {}, pre, formatUnits(1000n), st);
  w.rpc.state.impl = { block: 4n, tx: 548n };
  await assert.rejects(broadcast(w.rpc, s.hex, pre.plan, st), code('impl'));
  assert.ok(!w.rpc.state.calls.includes('sendrawtransaction'));
  let prompted = false;
  const spy = { ...fakeWallet(w.accounts), sign: async () => { prompted = true; return ''; } };
  await assert.rejects(signAndCheck(w.rpc, spy, {}, pre, formatUnits(1000n), st), code('impl'));
  assert.equal(prompted, false, 'the wallet is never asked');
});

test('poisoned twin — the node would reject: mempool gate stops before broadcast', async () => {
  const w = world({ mempool: () => ({ allowed: false, 'reject-reason': 'bad-txns-inputs-missingorspent' }) });
  const { st, pre } = await runToPreflight(w, 1000n);
  const s = await signAndCheck(w.rpc, fakeWallet(w.accounts), {}, pre, formatUnits(1000n), st);
  await assert.rejects(mempoolCheck(w.rpc, s.hex, pre.plan), code('mempool'));
  assert.ok(!w.rpc.state.calls.includes('sendrawtransaction'));
});

test('one preflight pins every view to one block tag and stays inside the rate budget', async () => {
  const w = world();
  await runToPreflight(w, 1000n);
  const views = w.rpc.state.calls.filter((c) => c.startsWith('metashrew_view'));
  // 1 batch of token views + impl pointer + bytecode + 3 FIRE-address coins + 1 fee coin (80,000 sats covers the
  // 20,000 asked) + 1 simulation batch
  assert.equal(views.length, 8);
  assert.equal(w.rpc.state.calls.filter((c) => c === 'metashrew_view:multisimluate').length, 2);
  void randomBytes;
});

test('single-address wallet (UniSat / SUBFROST style): change pays the same script, alkanes still only on output 0', async () => {
  const holder = randTaprootAccount();
  const acct = { ...holder, ...addressToScript(holder.address) };
  const accounts = { alkanes: acct, payment: acct };
  const coins = [
    { address: holder.address, txid: randTxid(), vout: 0, value: 546n, height: H - 9, alkanes: [{ id: FIRE, amount: 777n }] },
    { address: holder.address, txid: randTxid(), vout: 1, value: 30000n, height: H - 9, alkanes: [] },
  ];
  const rpc = fakeChain({ coins });
  const w = { rpc, accounts, reviewed: { '4:512': rpc.bytecodeSha } };
  const { st, pre } = await runToPreflight(w, 700n);
  assert.equal(pre.plan.tx.outputs.length, 3);
  assert.deepEqual([...pre.desc.route.outputs.keys()], [0], 'alkanes ride only on output 0, never on the change');
  assert.equal(pre.holderGets.get(FIRE_KEY), 77n);
  const s = await signAndCheck(rpc, fakeWallet(accounts), {}, pre, formatUnits(700n), st);
  assert.equal(await broadcast(rpc, s.hex, pre.plan, st), pre.plan.txid);
});

test('fee search: a dirty largest coin does not count toward the target; the search continues to clean coins', async () => {
  const w = world({ feeCoins: [
    { txid: randTxid(), vout: 0, value: 900000n, height: H - 5, alkanes: [{ id: { block: 2n, tx: 0n }, amount: 7n }] },
    { txid: randTxid(), vout: 1, value: 800000n, height: H - 5, alkanes: [], ord: { indexed: true, inscriptions: ['x'], runes: {} } },
    { txid: randTxid(), vout: 2, value: 30000n, height: H - 5, alkanes: [] },
  ] });
  const st = await readFire(w.rpc, { reviewed: w.reviewed });
  const coins = await loadCoins(w.rpc, w.accounts, st.height);
  const fee = await verifyFeeCoins(w.rpc, coins.filter((c) => c.value > 1000n), w.accounts, st.tag, st.height, 20000n);
  assert.deepEqual(fee.clean.map((c) => c.value), [30000n], 'the only clean coin is found despite two larger dirty ones');
  assert.equal(fee.rejected.length, 2);
});
