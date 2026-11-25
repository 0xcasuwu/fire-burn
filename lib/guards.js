// lib/guards.js — the safety gates. Each is a pure function that throws GateError(code, message) or returns.
// Every gate has a unit test AND a poisoned twin (a concrete bad input shown to fail with THIS gate's code) in
// test/guards.test.js. The page calls them in this order: coins (gateFireCoins, gateFeeCoins) → amount → plan →
// gatePointers on the decoded bytes → gateDecimals/gateImpl/gateSimulation (live) → gateFee → typed confirmation →
// wallet → gateSignedTx → testmempoolaccept → broadcast.
//
// Threat ids (T1…T11) refer to the catalogue in lib/burn.js.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { equalBytes } from './bytes.js';
import { isOpReturn } from './alkanes.js';
import { FIRE_ID, FIRE_KEY, OP_BURN, FIRE_DECIMALS, FIRE_MAX_SUPPLY_WHOLE, REVIEWED_IMPLS, ALKANES_GENESIS_HEIGHT, CHANGE_DUST, formatUnits } from './burn.js';
import { scriptType } from './address.js';
import { txid as computeTxid } from './tx.js';

export class GateError extends Error {
  constructor(code, message) { super(`[${code}] ${message}`); this.code = code; }
}
const fail = (code, msg) => { throw new GateError(code, msg); };

/** Gate 3 (T2): 0 < N ≤ balance, exact BigInt. */
export function gateAmount(amount, balance) {
  if (typeof amount !== 'bigint' || typeof balance !== 'bigint') fail('amount', 'amount and balance must be exact integers');
  if (amount <= 0n) fail('amount', 'amount must be greater than zero (an edict of 0 would move the whole balance)');
  if (amount > balance) fail('amount', `amount ${amount} exceeds the verified balance ${balance}`);
}

/** T10: the live max supply must be 2,100,000 × 10^DECIMALS, or the decimals we display are wrong. */
export function gateDecimals(maxSupply) {
  const want = FIRE_MAX_SUPPLY_WHOLE * 10n ** BigInt(FIRE_DECIMALS);
  if (maxSupply !== want) fail('decimals', `GetMaxSupply = ${maxSupply}, expected ${want} (2,100,000 FIRE at ${FIRE_DECIMALS} decimals)`);
}

/** T6: 2:77623's implementation must be one whose burn() was reviewed, with the reviewed bytes. */
export function gateImpl({ implId, bytecodeSha256 }, reviewed = REVIEWED_IMPLS) {
  const want = Object.prototype.hasOwnProperty.call(reviewed, implId) ? reviewed[implId] : undefined;
  if (!want) fail('impl', `2:77623 now runs ${implId}, an implementation this page has not reviewed — refusing`);
  if (bytecodeSha256 !== want) fail('impl', `${implId} bytecode sha256 ${bytecodeSha256} ≠ reviewed ${want}`);
}

function isCleanOrdRow(row) {
  if (!row || row.indexed !== true) return { ok: false, why: 'ord has not indexed it' };
  if (!Array.isArray(row.inscriptions)) return { ok: false, why: 'ord gave no inscription list' };
  if (row.inscriptions.length) return { ok: false, why: `carries ${row.inscriptions.length} inscription(s)` };
  const r = row.runes;
  const runeCount = Array.isArray(r) ? r.length : r && typeof r === 'object' ? Object.keys(r).length : null;
  if (runeCount === null) return { ok: false, why: 'ord gave no rune list' };
  if (runeCount) return { ok: false, why: `carries ${runeCount} rune balance(s)` };
  return { ok: true };
}

function coinBasics(c, indexerHeight, code) {
  const op = `${c.txid}:${c.vout}`;
  if (!c.confirmed || !c.height) fail(code, `${op} is unconfirmed`);
  if (c.height > indexerHeight) fail(code, `${op} (block ${c.height}) is above the alkanes indexer (${indexerHeight})`);
  return op;
}

/** Gate 2 (T4, T5, T11): a fee coin carries no alkanes (read by outpoint), no inscriptions, no runes, and all three are VERIFIED. */
export function gateFeeCoins(coins, { alkanes, ord, indexerHeight }) {
  for (const c of coins) {
    const op = coinBasics(c, indexerHeight, 'fee-coin');
    const a = alkanes.get(op);
    if (!a) fail('fee-coin', `${op}: alkanes not read`);
    if (a.empty && c.height >= ALKANES_GENESIS_HEIGHT) fail('fee-coin', `${op}: the indexer has no row for it — unverifiable, refusing`);
    if (a.entries.length) fail('fee-coin', `${op} carries alkanes — never spent as fee`);
    const o = isCleanOrdRow(ord.get(op));
    if (!o.ok) fail('fee-coin', `${op}: ${o.why}`);
  }
}

/** FIRE coins: confirmed, indexed, FIRE present, and no inscription/rune that sat-flow could carry elsewhere. */
export function gateFireCoins(coins, { alkanes, ord, indexerHeight }) {
  for (const c of coins) {
    const op = coinBasics(c, indexerHeight, 'fire-coin');
    const a = alkanes.get(op);
    if (!a || a.empty) fail('fire-coin', `${op}: alkanes not read`);
    const fire = a.entries.filter((e) => e.id.block === FIRE_ID.block && e.id.tx === FIRE_ID.tx).reduce((s, e) => s + e.amount, 0n);
    if (fire === 0n) fail('fire-coin', `${op} carries no FIRE`);
    const o = isCleanOrdRow(ord.get(op));
    if (!o.ok) fail('fire-coin', `${op}: ${o.why}`);
  }
}

const sameIdAs = (id, ref) => id.block === ref.block && id.tx === ref.tx;

/**
 * Gate 1 (T1, T2, T3) on the DECODED tx (describeBurnTx output):
 * exactly the two-stone shape, every pointer/refund (and the runestone pointer) on the holder's own output,
 * p0's single edict = [FIRE, N → shadow(p1)], p1 = [2,77623,88], and the routing replay puts every alkane on the
 * holder's output except the N FIRE the call consumes.
 */
export function gatePointers(desc, tx, { holderScript, amount, inputSheets }) {
  const n = tx.outputs.length;
  // The alkanes output is output 0 BY CONSTRUCTION (lib/burn.js planBurn) and must pay the holder's script. Every
  // pointer must name exactly that index — not merely "an output with the holder's script": a single-address wallet's
  // BTC change pays the same script, and alkanes must never ride on the change coin.
  const holderIdx = 0;
  if (!n || !equalBytes(tx.outputs[holderIdx].script, holderScript)) fail('pointers', "output 0 does not pay the holder's address");
  const holderAt = (v) => v !== undefined && v === BigInt(holderIdx);
  if (!holderAt(desc.runestone.pointer)) fail('pointers', 'runestone pointer is not the holder output');
  if (desc.stones.length !== 2) fail('pointers', `expected 2 protostones, found ${desc.stones.length}`);
  desc.stones.forEach((s, i) => {
    if (s.protocolTag !== 1n) fail('pointers', `protostone ${i} is not alkanes (tag ${s.protocolTag})`);
    if (s.burn !== undefined || s.from !== undefined) fail('pointers', `protostone ${i} carries burn/from fields`);
    if (s.unknownKeys.length || s.repeatedKeys.length || s.edictsMalformed) fail('pointers', `protostone ${i} has unexpected fields`);
    if (!holderAt(s.pointer)) fail('pointers', `protostone ${i} pointer does not point at the holder output`);
    if (!holderAt(s.refund)) fail('pointers', `protostone ${i} refund does not point at the holder output`);
  });
  const [p0, p1] = desc.stones;
  if (p0.message.length) fail('pointers', 'p0 must carry no call');
  if (p0.edicts.length !== 1) fail('pointers', `p0 must carry exactly one edict, found ${p0.edicts.length}`);
  const e = p0.edicts[0];
  if (!sameIdAs(e.id, FIRE_ID)) fail('pointers', 'p0 edict is not FIRE');
  if (e.amount !== amount || amount <= 0n) fail('pointers', `p0 edict amount ${e.amount} ≠ ${amount}`);
  if (e.output !== BigInt(n + 2)) fail('pointers', `p0 edict goes to ${e.output}, not p1's shadow vout ${n + 2}`);
  if (p1.edicts.length) fail('pointers', 'p1 must carry no edicts');
  const cp = desc.cellpacks[1];
  if (!cp || !sameIdAs(cp.target, FIRE_ID) || cp.inputs[0] !== OP_BURN || cp.inputs.slice(1).some((x) => x !== 0n)) {
    fail('pointers', 'p1 is not exactly the FIRE Burn call [2, 77623, 88]');
  }
  // routing replay
  if (desc.route.lost.size) fail('pointers', 'some alkanes would land on the OP_RETURN or a virtual output (lost)');
  for (const [v] of desc.route.outputs) if (v !== holderIdx) fail('pointers', `alkanes would land on output ${v}, not the holder output`);
  if (desc.burned !== amount) fail('pointers', `the call would burn ${desc.burned}, not ${amount}`);
  const want = new Map();
  for (const m of inputSheets) for (const [k, v] of m) want.set(k, (want.get(k) || 0n) + v);
  want.set(FIRE_KEY, (want.get(FIRE_KEY) || 0n) - amount);
  const got = desc.route.outputs.get(holderIdx) || new Map();
  for (const [k, v] of want) if (v > 0n && got.get(k) !== v) fail('pointers', `${k}: holder would receive ${got.get(k) || 0n}, expected ${v}`);
  for (const [k, v] of got) if ((want.get(k) || 0n) !== v) fail('pointers', `${k}: holder would receive ${v}, expected ${want.get(k) || 0n}`);
}

/** T1 (outputs): every output is the holder's alkanes output, the user's change output, or the one OP_RETURN. */
export function gateOutputs(tx, { holderScript, changeScript }) {
  tx.outputs.forEach((o, i) => {
    if (isOpReturn(o.script)) { if (o.value !== 0n) fail('outputs', `OP_RETURN output ${i} carries ${o.value} sats`); return; }
    if (!equalBytes(o.script, holderScript) && !(changeScript && equalBytes(o.script, changeScript))) fail('outputs', `output ${i} pays a script that is not the user's`);
  });
}

/** Gate 4 (T7): the live simulation consumed exactly N and the supply counter moves by the incoming amount. */
export function gateSimulation({ amount, supply, burnN, burnS, burnS1 }) {
  if (!burnN || !burnN.ok) fail('simulation', `burning ${amount} reverted: ${burnN && burnN.error}`);
  // zero-value entries are nothing (the indexer's own traces carry them, e.g. golden tx 34e20e61…'s exit)
  const returned = burnN.returned.filter((t) => t.value > 0n);
  if (returned.some((t) => sameIdAs(t.id, FIRE_ID))) fail('simulation', 'the call returned FIRE (not all of it was burned)');
  if (returned.length) fail('simulation', 'the call returned alkanes it was never given');
  if (!burnS || !burnS.ok) fail('simulation', `burning the whole live supply (${supply}) reverted — the decrement is not the incoming amount`);
  if (!burnS1 || burnS1.ok) fail('simulation', `burning supply + 1 did NOT revert — the decrement is not the incoming amount`);
  // an empty parcel answer is ANY failure (src/lib.rs:72-79); only the supply underflow proves the decrement
  // (live 977,471: "ALKANES: revert: Error: Extcall failed: ALKANES: revert: Error: overflow error")
  if (!/overflow/i.test(String(burnS1.error))) fail('simulation', `burning supply + 1 failed for another reason (${burnS1.error}) — not proof of the decrement`);
  if (amount > supply) fail('simulation', 'amount exceeds the live total supply');
}

/**
 * T9: the fee is what the plan said and not absurd. Allowed above rate × size: 50 % + 2 sat/vB of slack, plus the
 * change the planner may drop into the fee (below CHANGE_DUST) and the change output it then saves (43 vB) — without
 * that, a no-change plan from small FIRE coins at 1 sat/vB was refused (review finding 5).
 * A fee rate typed 10× too high inside these bounds is shown, not separately confirmed (residual, in the report).
 */
export const MAX_FEE_SATS = 100_000n;
export const MAX_FEE_RATE = 300;
export function gateFee(plan, desc) {
  if (desc.fee !== plan.fee) fail('fee', `decoded fee ${desc.fee} ≠ planned ${plan.fee}`);
  if (desc.fee <= 0n) fail('fee', 'fee must be positive');
  if (!(plan.feeRate >= 1 && plan.feeRate <= MAX_FEE_RATE)) fail('fee', `fee rate ${plan.feeRate} is outside 1..${MAX_FEE_RATE} sat/vB`);
  if (desc.fee > MAX_FEE_SATS) fail('fee', `fee ${desc.fee} sats exceeds the ${MAX_FEE_SATS}-sat ceiling`);
  const allowed = Math.ceil(plan.feeRate * plan.estVsize * 1.5) + 2 * plan.estVsize + Number(CHANGE_DUST) + Math.ceil(43 * plan.feeRate);
  if (Number(desc.fee) > allowed) fail('fee', `fee ${desc.fee} sats is far above ${plan.feeRate} sat/vB × ${plan.estVsize} vB`);
}

/** Gate 5: the user typed exactly the amount shown. */
export function gateTypedConfirmation(typed, amount, decimals = FIRE_DECIMALS) {
  const want = formatUnits(amount, decimals);
  if (typeof typed !== 'string' || typed.trim() !== want) fail('confirm', `type ${want} exactly to confirm`);
}

/**
 * R7 / T8: the signed tx is the tx we built (same txid ⇒ same inputs, outputs, amounts), and every input is signed
 * with a sighash that commits to ALL inputs and outputs. The txid excludes witnesses, so a wallet that signed an
 * input SINGLE|ANYONECANPAY or NONE would pass the txid check and let a third party re-spend that input with its own
 * outputs (review finding 2). Taproot key path: 64-byte signature (DEFAULT) or 65 bytes ending 0x01 (ALL); segwit v0:
 * DER signature ending 0x01 plus a 33-byte compressed key.
 */
export function gateSignedTx(signed, plan) {
  const got = computeTxid(signed);
  if (got !== plan.txid) fail('signed', `the wallet changed the transaction (txid ${got} ≠ built ${plan.txid}) — refusing to broadcast`);
  signed.inputs.forEach((i, k) => {
    const w = i.witness || [];
    if (!w.length) fail('signed', `input ${k} is not signed`);
    const kind = scriptType(plan.coins[k].script);
    if (kind === 'p2tr') {
      if (w.length !== 1) fail('signed', `input ${k}: expected a taproot key-path witness (1 item), got ${w.length}`);
      const sig = w[0];
      if (!(sig.length === 64 || (sig.length === 65 && sig[64] === 0x01))) fail('signed', `input ${k}: taproot signature does not commit to the whole transaction`);
    } else {
      if (w.length !== 2 || w[1].length !== 33) fail('signed', `input ${k}: expected [signature, compressed key]`);
      const sig = w[0];
      if (sig.length < 9 || sig[0] !== 0x30 || sig[sig.length - 1] !== 0x01) fail('signed', `input ${k}: signature is not DER with SIGHASH_ALL`);
    }
  });
}
