// test/route.test.js — the protorune routing model (lib/route.js) on the burn shape and on the shapes it must
// refuse or that show WHY the two-stone design is needed. Poisoned twins: the brief's one-stone layout burns the
// whole coin; edict amount 0 moves everything; an over-sized edict is clamped to the balance.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { routeProtostones } from '../lib/route.js';
import { fireBurnOutcome, FIRE_KEY, FIRE_ID } from '../lib/burn.js';
import { encodeCellpack, runestoneScript, encipherProtostones, decipherProtostones } from '../lib/alkanes.js';

const OPR = Uint8Array.of(0x6a, 0x5d);
const P2TR = new Uint8Array(34).fill(1);
const CHG = new Uint8Array(22).fill(2);
const OTHER = '2:69805';
const burnCall = encodeCellpack(FIRE_ID, [88n]);
const sheet = (o) => new Map(Object.entries(o).map(([k, v]) => [k, BigInt(v)]));
const stonesFrom = (list) => decipherProtostones(encipherProtostones(list));

function run(stones, inputs, outs = [P2TR, CHG, OPR]) {
  return routeProtostones({ inputSheets: inputs, outputScripts: outs, protostones: stonesFrom(stones), callOutcome: fireBurnOutcome });
}

test('two-stone burn: exactly N reaches the call, the rest of FIRE and every other alkane land on v0', () => {
  const N = 1234n;
  const r = run([
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: N, output: 5 }], message: new Uint8Array(0) },
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: burnCall },
  ], [sheet({ [FIRE_KEY]: 10000, [OTHER]: 1 }), sheet({ [FIRE_KEY]: 5 }), new Map()]);
  assert.equal(r.calls.length, 1);
  assert.equal(r.calls[0].incoming.get(FIRE_KEY), N);
  assert.equal(r.calls[0].incoming.size, 1, 'the call receives FIRE only');
  assert.equal(r.calls[0].ok, true);
  assert.deepEqual([...r.outputs.keys()], [0]);
  assert.equal(r.outputs.get(0).get(FIRE_KEY), 10005n - N);
  assert.equal(r.outputs.get(0).get(OTHER), 1n);
  assert.equal(r.lost.size, 0);
});

test('poisoned twin — the one-stone layout of the first brief burns the WHOLE input FIRE, not N', () => {
  const N = 1234n;
  const r = run([
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: N, output: 4 }], message: burnCall },
  ], [sheet({ [FIRE_KEY]: 10000, [OTHER]: 1 })]);
  assert.equal(r.calls[0].incoming.get(FIRE_KEY), 10000n, 'every input alkane goes to the first protostone (lib.rs:1010-1020)');
  assert.equal((r.outputs.get(0) || new Map()).get(FIRE_KEY), undefined, 'no FIRE comes back');
});

test('revert refunds the routed FIRE to the refund pointer; the stone\'s edicts do not run', () => {
  const r = routeProtostones({
    inputSheets: [sheet({ [FIRE_KEY]: 50 })], outputScripts: [P2TR, CHG, OPR],
    protostones: stonesFrom([
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: 20n, output: 5 }], message: new Uint8Array(0) },
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: burnCall },
    ]),
    callOutcome: () => ({ ok: false, returned: new Map() }),
  });
  assert.equal(r.outputs.get(0).get(FIRE_KEY), 50n);
});

test('poisoned twins — edict amount 0 moves everything; an amount above the balance is clamped to it', () => {
  for (const amount of [0n, 99999n]) {
    const r = run([
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount, output: 5 }], message: new Uint8Array(0) },
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: burnCall },
    ], [sheet({ [FIRE_KEY]: 777 })]);
    assert.equal(r.calls[0].incoming.get(FIRE_KEY), 777n, `amount ${amount} burns the whole balance`);
  }
});

test('poisoned twins — pointer at the OP_RETURN or a shadow vout loses the alkanes (reported in `lost`)', () => {
  const r = run([
    { protocolTag: 1n, pointer: 2, refund: 2, edicts: [{ id: FIRE_ID, amount: 1n, output: 5 }], message: new Uint8Array(0) },
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: burnCall },
  ], [sheet({ [FIRE_KEY]: 10, [OTHER]: 3 })]);
  assert.ok(r.lost.has(2), 'leftover lands on the OP_RETURN');
  assert.equal(r.lost.get(2).get(OTHER), 3n);
  // an edict to a shadow vout with no protostone behind it
  const r2 = run([
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: 4n, output: 9 }], message: new Uint8Array(0) },
  ], [sheet({ [FIRE_KEY]: 10 })]);
  assert.equal(r2.lost.get(9).get(FIRE_KEY), 4n);
});

test('poisoned twin — an edict to output == numOutputs (spread) is refused by the model', () => {
  assert.throws(() => run([
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: 1n, output: 3 }], message: new Uint8Array(0) },
  ], [sheet({ [FIRE_KEY]: 10 })]), /spreads over every output/);
});

test('model follows the golden mainnet swap 34e20e61… layout: p0 edict to shadow 6 with 4 outputs delivers exactly N', () => {
  // 4 outputs (3 + OP_RETURN) → shadow(p1) = 4 + 1 + 1 = 6, as on chain; fire-analytics trace ledger recorded inFire 380000000 at vout 6
  const outs = [P2TR, P2TR, CHG, OPR];
  const r = routeProtostones({
    inputSheets: [sheet({ [FIRE_KEY]: 1000000000 })], outputScripts: outs,
    protostones: stonesFrom([
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount: 380000000n, output: 6 }], message: new Uint8Array(0) },
      { protocolTag: 1n, pointer: 7, refund: 0, edicts: [], message: encodeCellpack({ block: 4n, tx: 65522n }, [13n]) },
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: encodeCellpack({ block: 32n, tx: 0n }, [78n]) },
    ]),
    callOutcome: (s) => ({ ok: true, returned: new Map(), consumed: s }),
  });
  assert.equal(r.calls[0].incoming.get(FIRE_KEY), 380000000n);
  assert.equal(r.outputs.get(0).get(FIRE_KEY), 620000000n);
  void runestoneScript;
});
