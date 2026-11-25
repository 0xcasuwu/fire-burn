// lib/burn.js — FIRE burn: constants, the transaction plan, and the decoder that re-reads a built tx.
//
// ── SPEC (requirements; MUST = a violation loses funds) ────────────────────────────────────────────────
//  R1 MUST burn EXACTLY the typed amount N (base units) of FIRE and no other alkane. [operator brief]
//  R2 MUST return every other FIRE unit and every other alkane on the spent coins to the holder's own address,
//     on success AND on revert (pointer = refund = the holder's output). [brief; app "shifter" pattern,
//     subfrost-app CLAUDE.md "Protostone Patterns"]
//  R3 MUST NOT spend a fee coin that carries alkanes, inscriptions or runes (checked per outpoint). [brief gate 2]
//  R4 MUST refuse N = 0 (an edict amount of 0 moves EVERYTHING, crates/protorune/src/lib.rs:335) and N > balance
//     (an edict above the balance is clamped to the balance, i.e. burns everything). [brief gate 3; source]
//  R5 MUST show, before the wallet prompt, what the BYTES do (decoded, not intended) and refuse if a live
//     simulation fails or does not consume exactly N. [brief gate 4]
//  R6 MUST require the user to type the amount before signing. [brief gate 5]
//  R7 MUST refuse to broadcast a signed tx whose txid differs from the one built (a wallet that rewrites outputs
//     or fees — the SUBFROST extension's fee patch does exactly that, subfrost-app lib/wallet/subfrostFeePatch.ts).
//  R8 MUST target the canonical FIRE proxy 2:77623 (core crates/subfrost-wallet-common/src/canonical_alkanes.rs:47)
//     and refuse when its implementation is not one whose burn() was reviewed (see REVIEWED_IMPLS).
//
// ── DESIGN (and why it differs from the first brief) ──────────────────────────────────────────────────
// The brief proposed ONE protostone carrying the cellpack plus an edict of N to itself. The indexer gives EVERY
// input alkane to the first alkanes protostone (lib.rs:1010-1020) and runs a message stone's edicts only AFTER the
// call, on the pointer's sheet (lib.rs:1036-1056). With one stone the burn would receive the user's WHOLE FIRE
// coin and burn all of it. So the tx uses the app's two-stone "shifter" (the same shape as every app FIRE call):
//   outputs: v0 holder's alkanes address (600 sats) · v1 BTC change to the fee payer (omitted below dust) · OP_RETURN
//   p0 (no message): edict [FIRE, N → shadow(p1)], pointer v0, refund v0 → the rest of the FIRE and all other
//      alkanes fall through to v0.
//   p1: cellpack [2, 77623, 88], pointer v0, refund v0 → receives exactly N FIRE; a revert refunds them to v0.
//   Runestone pointer v0 (ord runes, if any, also land on v0; never on the OP_RETURN).
// shadow(i) = numOutputs + 1 + i (lib.rs:1023; the CLI writes num_physical_outputs + 2 + p because it counts
// outputs before adding the OP_RETURN, alkanes-cli-common execute.rs:1151).
//
// ── THREATS (each has a guard in lib/guards.js and a poisoned-twin test) ──────────────────────────────
//  T1 pointer/refund at the OP_RETURN or a foreign script → alkanes lost/stolen          → gatePointers
//  T2 edict amount 0 / > balance → whole balance burned                                 → gateAmount, gatePointers
//  T3 edict to output == numOutputs → spread to every output incl. change               → gatePointers
//  T4 fee coin carries alkanes / inscription / runes → destroyed or given away          → gateFeeInputs
//  T5 unverifiable fee coin (ord not indexed, indexer "no row") read as clean           → gateFeeInputs (empty ≠ safe)
//  T6 FIRE impl swapped (v3 lane) to code whose op 88 does something else               → gateImpl
//  T7 simulation revert read as success / partial burn                                 → gateSimulation
//  T8 wallet rewrites outputs / fee while signing                                       → gateSignedTx
//  T9 fee far above intent (rate outside 1..300, > 100k sats, or far above rate × size)   → gateFee
//     (residual: a rate typed 10× too high INSIDE those bounds is shown in the review, not separately confirmed)
//  T10 decimals assumed wrong → off by 10^k                                             → gateDecimals
//  T11 spending an unconfirmed or not-yet-indexed coin (indexer has no row yet)         → coin filters
//  T12 wallet signs with a sighash that does not cover every input/output (txid unchanged) → gateSignedTx
//  T13 FIRE repointed while the page is open (checks done at an older height)            → recheckImpl before
//      the wallet prompt and before broadcast
//
// JOURNAL
//  2026-11-25 created for fire-burn. Live checks at 977,470: 2:77623 name/symbol "FIRE", op 102 = 2.1e14,
//   /implementation = 4:512 (bytecode sha256 ac17d1f7…dde = fire-migration impl_4-512_live.wasm), op 88 with
//   1,000 FIRE units credited: success, nothing returned, 154,581 fuel.
//  2026-11-25 independent review (no Critical/High): sighash check on returned signatures, impl re-read before sign
//   and broadcast, supply+1 must fail with the underflow, fee gate allows dropped dust, SUBFROST fee floor, exact-
//   cellpack simulation, UI generation guards, no second build from a spent scan. Open items are in the report.

import { encodeCellpack, encipherProtostones, runestoneScript, decodeRunestoneScript, decipherProtostones, decodeCellpack, isOpReturn } from './alkanes.js';
import { scriptType } from './address.js';
import { estimateVsize, inputTypeOfScript, txid as computeTxid } from './tx.js';
import { routeProtostones, idKey } from './route.js';

export const FIRE_ID = Object.freeze({ block: 2n, tx: 77623n });
export const FIRE_KEY = idKey(FIRE_ID);
export const OP_BURN = 88n;
/** fire-constants/src/lib.rs:73 (DECIMALS = 8) and :83 (MAX_SUPPLY = 2_100_000 * 10^8); checked live by gateDecimals. */
export const FIRE_DECIMALS = 8;
export const FIRE_MAX_SUPPLY_WHOLE = 2_100_000n;
/** subfrost-app CLAUDE.md "DUST_VALUE = 600 sats (not 546) for relay compatibility". */
export const ALKANES_OUTPUT_SATS = 600n;
/** Change below this is dropped into the fee (546 = the p2pkh dust bound, the most conservative of the kinds we pay to). */
export const CHANGE_DUST = 546n;
/** Pre-genesis outputs can carry no alkanes (subfrost-app protorunesByOutpointMV.ts: first indexed block 880000). */
export const ALKANES_GENESIS_HEIGHT = 880000;

/**
 * Implementations of 2:77623 whose op 88 was read in source. Key = "block:tx", value = sha256 of the bytecode.
 *  4:512 — LIVE today. Source: fire-migration/alkanes/fire-token_2-77623/source/fire-token/src/lib.rs:253-277
 *          (find the FIRE entry, refuse none/zero, decrease_total_supply(value), return every non-FIRE entry).
 *  4:548 — FIRE v3 "TO" token staged by the one-deploy (memory project_fire_v3_stage_a_done_20261121); Stage B
 *          would repoint 2:77623 here. Source: wt-fire-v3-g8 alkanes/fire-token/src/lib.rs:390-420 (sums EVERY
 *          FIRE entry, same refusals, same refund rule). Bytes not rebuilt by this repo; sha read on chain.
 */
export const REVIEWED_IMPLS = Object.freeze({
  '4:512': 'ac17d1f7637d679c77d1530174030a4a6a9d34baccc6ae2608a0420ed9c84dde',
  '4:548': 'f6360c59097ef5a4875516706eccfc6531cee293c404aa58ebe11e66e3e22bab',
});

/** The burn's effect, from the reviewed source: consume every FIRE entry (refuse none / zero), return the rest. */
export function fireBurnOutcome(sheet) {
  const fire = sheet.get(FIRE_KEY) || 0n;
  if (fire === 0n) return { ok: false, returned: new Map(), reason: 'no FIRE tokens to burn' };
  const returned = new Map([...sheet].filter(([k, v]) => k !== FIRE_KEY && v > 0n));
  return { ok: true, returned, consumed: new Map([[FIRE_KEY, fire]]) };
}

/** Whole-units string for base units (exact, no floats). */
export function formatUnits(base, decimals = FIRE_DECIMALS) {
  const b = BigInt(base);
  const neg = b < 0n;
  const a = neg ? -b : b;
  const s = a.toString().padStart(decimals + 1, '0');
  const whole = s.slice(0, s.length - decimals);
  const frac = s.slice(s.length - decimals).replace(/0+$/, '');
  return (neg ? '-' : '') + whole + (frac ? '.' + frac : '');
}

/** "12.5" → base units; refuses more decimals than the token has, signs, exponents, spaces. */
export function parseUnits(text, decimals = FIRE_DECIMALS) {
  if (typeof text !== 'string') throw new Error('amount: not text');
  const t = text.trim();
  const m = /^(\d+)(?:\.(\d+))?$/.exec(t);
  if (!m) throw new Error('amount: digits and at most one "." only');
  const frac = m[2] || '';
  if (frac.length > decimals) throw new Error(`amount: at most ${decimals} decimals`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
}

/** The final scriptSig a coin will carry: push(redeemScript) for p2sh-p2wpkh, empty for native segwit / taproot. */
export function scriptSigFor(c) {
  const r = c.meta && c.meta.redeemScript;
  if (!r) return new Uint8Array(0);
  if (r.length >= 0x4c) throw new Error('redeemScript too long');
  const out = new Uint8Array(r.length + 1);
  out[0] = r.length; out.set(r, 1);
  return out;
}

/**
 * Build the burn transaction.
 * @param p.amount        BigInt base units N
 * @param p.fireCoins     [{ txid, vout, value, script, alkanes: Map(idKey→amount), meta: psbtInputMeta }] already verified
 * @param p.feeCoins      [{ txid, vout, value, script, meta }] candidates, already verified clean, largest first
 * @param p.holderScript  scriptPubKey of the holder's alkanes address (v0)
 * @param p.changeScript  scriptPubKey for BTC change (fee payer's address)
 * @param p.feeRate       sat/vB (number, ≥ 1)
 */
export function planBurn({ amount, fireCoins, feeCoins, holderScript, changeScript, feeRate }) {
  if (typeof amount !== 'bigint') throw new Error('plan: amount must be a BigInt');
  if (!(feeRate >= 1 && feeRate <= 1000)) throw new Error('plan: fee rate must be 1..1000 sat/vB');
  // FIRE coins: largest FIRE first until N is covered (fewest alkane coins touched).
  const sorted = [...fireCoins].sort((a, b) => {
    const fa = a.alkanes.get(FIRE_KEY) || 0n, fb = b.alkanes.get(FIRE_KEY) || 0n;
    return fa === fb ? 0 : fa > fb ? -1 : 1;
  });
  const chosenFire = [];
  let fireIn = 0n;
  for (const c of sorted) {
    if (fireIn >= amount) break;
    const f = c.alkanes.get(FIRE_KEY) || 0n;
    if (f === 0n) continue;
    chosenFire.push(c);
    fireIn += f;
  }
  if (fireIn < amount) throw new Error('plan: not enough FIRE on the verified coins');

  const opReturnFor = (numOutputs) => {
    const p1 = numOutputs + 2; // shadow(1) = numOutputs + 1 + 1
    const stones = [
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE_ID, amount, output: p1 }], message: new Uint8Array(0) },
      { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: encodeCellpack(FIRE_ID, [OP_BURN]) },
    ];
    return runestoneScript({ pointer: 0, protocol: encipherProtostones(stones) });
  };

  const chosenFee = [];
  const inputsValue = () => [...chosenFire, ...chosenFee].reduce((s, c) => s + c.value, 0n);
  const inputTypes = () => [...chosenFire, ...chosenFee].map((c) => inputTypeOfScript(c.script));
  for (let k = 0; k <= feeCoins.length; k++) {
    // try with change, then without (change below dust is dropped into the fee)
    for (const withChange of [true, false]) {
      const n = withChange ? 3 : 2;
      const opr = opReturnFor(n);
      const scripts = withChange ? [holderScript, changeScript, opr] : [holderScript, opr];
      const vsize = estimateVsize(inputTypes(), scripts);
      const fee = BigInt(Math.ceil(vsize * feeRate));
      const change = inputsValue() - ALKANES_OUTPUT_SATS - fee;
      if (withChange ? change >= CHANGE_DUST : change >= 0n) {
        const outputs = [{ value: ALKANES_OUTPUT_SATS, script: holderScript }];
        if (withChange) outputs.push({ value: change, script: changeScript });
        outputs.push({ value: 0n, script: opr });
        const coins = [...chosenFire, ...chosenFee];
        const tx = {
          version: 2, locktime: 0,
          // a p2sh-p2wpkh input's scriptSig (push of its redeemScript) is part of the txid, and is known before
          // signing — set it here so plan.txid IS the final txid (createPsbt clears scriptSigs for the PSBT).
          inputs: coins.map((c) => ({ txid: c.txid, vout: c.vout, sequence: 0xfffffffd, scriptSig: scriptSigFor(c), witness: [] })),
          outputs,
        };
        const totalOut = outputs.reduce((s, o) => s + o.value, 0n);
        return {
          tx, coins, txid: computeTxid(tx), fireIn, amount,
          fee: inputsValue() - totalOut, estVsize: vsize, feeRate,
          feeCoinsUsed: chosenFee.length, fireCoinsUsed: chosenFire.length, change: withChange ? change : 0n,
        };
      }
    }
    if (k === feeCoins.length) break;
    chosenFee.push(feeCoins[k]);
  }
  throw new Error('plan: not enough clean BTC to pay the fee');
}

/**
 * Re-read a built (or signed) tx from its bytes: decode the runestone, decipher the protostones, replay the
 * indexer's routing over the per-input alkanes, and summarise. Pure; the guards decide.
 * @param tx           parsed/built tx
 * @param inputSheets  Map<string,bigint>[] per input (from protorunesbyoutpoint)
 * @param prevouts     [{ value: BigInt, script }] per input
 */
export function describeBurnTx(tx, inputSheets, prevouts) {
  const scripts = tx.outputs.map((o) => o.script);
  const opIdx = scripts.map((s, i) => (isOpReturn(s) ? i : -1)).filter((i) => i >= 0);
  if (opIdx.length !== 1) throw new Error(`expected exactly one OP_RETURN output, found ${opIdx.length}`);
  const rs = decodeRunestoneScript(scripts[opIdx[0]], scripts.length);
  const stones = decipherProtostones(rs.protocol);
  const cellpacks = stones.map((s) => (s.message.length ? decodeCellpack(s.message) : null));
  const route = routeProtostones({ inputSheets, outputScripts: scripts, protostones: stones, callOutcome: (sheet, stone) => {
    const cp = decodeCellpack(stone.message);
    if (cp.target.block !== FIRE_ID.block || cp.target.tx !== FIRE_ID.tx || cp.inputs[0] !== OP_BURN) {
      return { ok: false, returned: new Map(), reason: 'not a FIRE burn call' };
    }
    return fireBurnOutcome(sheet);
  } });
  const inValue = prevouts.reduce((s, p) => s + p.value, 0n);
  const outValue = tx.outputs.reduce((s, o) => s + o.value, 0n);
  const burned = route.calls.filter((c) => c.ok).reduce((s, c) => s + ((c.consumed && c.consumed.get(FIRE_KEY)) || 0n), 0n);
  const fireInputs = inputSheets.reduce((s, m) => s + (m.get(FIRE_KEY) || 0n), 0n);
  return {
    runestone: rs, stones, cellpacks, route, burned, fireInputs,
    fee: inValue - outValue, inValue, outValue,
    outputKinds: scripts.map(scriptType),
  };
}

