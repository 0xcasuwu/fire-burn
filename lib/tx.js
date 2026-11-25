// lib/tx.js — Bitcoin transaction (de)serialization, txid, weight/vsize, and size estimates for fee planning.
//
// SHAPE: { version, locktime, inputs: [{ txid (display hex), vout, sequence, scriptSig: Uint8Array,
//          witness: Uint8Array[] }], outputs: [{ value: BigInt sats, script: Uint8Array }] }
// The txid excludes witness data, so "the signed tx has the txid we built" proves the wallet changed no input,
// output, amount, sequence, version or locktime (the post-sign gate in lib/guards.js relies on this).
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { Reader, bytesToHex, compactSize, concat, hexToBytes, reversed, u32le, u64le } from './bytes.js';
import { sha256d } from './sha256.js';
import { scriptType } from './address.js';

export function serializeTx(tx, { witness = true } = {}) {
  const hasWitness = witness && tx.inputs.some((i) => i.witness && i.witness.length);
  const parts = [u32le(tx.version)];
  if (hasWitness) parts.push(Uint8Array.of(0x00, 0x01));
  parts.push(compactSize(tx.inputs.length));
  for (const i of tx.inputs) {
    parts.push(reversed(hexToBytes(i.txid)), u32le(i.vout), compactSize(i.scriptSig.length), i.scriptSig, u32le(i.sequence));
  }
  parts.push(compactSize(tx.outputs.length));
  for (const o of tx.outputs) parts.push(u64le(o.value), compactSize(o.script.length), o.script);
  if (hasWitness) {
    for (const i of tx.inputs) {
      const w = i.witness || [];
      parts.push(compactSize(w.length));
      for (const item of w) parts.push(compactSize(item.length), item);
    }
  }
  parts.push(u32le(tx.locktime));
  return concat(...parts);
}

export function parseTx(bytes) {
  const r = new Reader(bytes);
  const version = r.u32();
  let segwit = false;
  if (r.b[r.o] === 0x00 && r.b[r.o + 1] === 0x01) { segwit = true; r.o += 2; }
  const nIn = r.compactSize();
  const inputs = [];
  for (let k = 0; k < nIn; k++) {
    const txid = bytesToHex(reversed(r.bytes(32)));
    const vout = r.u32();
    const scriptSig = r.varBytes();
    const sequence = r.u32();
    inputs.push({ txid, vout, scriptSig, sequence, witness: [] });
  }
  const nOut = r.compactSize();
  const outputs = [];
  for (let k = 0; k < nOut; k++) outputs.push({ value: r.u64(), script: r.varBytes() });
  if (segwit) {
    for (const i of inputs) {
      const n = r.compactSize();
      for (let k = 0; k < n; k++) i.witness.push(r.varBytes());
    }
  }
  const locktime = r.u32();
  if (r.remaining !== 0) throw new Error('tx: trailing bytes');
  return { version, locktime, inputs, outputs };
}

export function txid(tx) { return bytesToHex(reversed(sha256d(serializeTx(tx, { witness: false })))); }

export function weight(tx) {
  const base = serializeTx(tx, { witness: false }).length;
  const total = serializeTx(tx, { witness: true }).length;
  return base * 3 + total;
}

export function vsize(tx) { return Math.ceil(weight(tx) / 4); }

/**
 * Input weight (WU) for a FINALIZED input of each script type, used to plan the fee before signing.
 * p2tr key path: 41 B base ×4 + witness (1 count + 1 len + 64 sig + 1 margin for a 65-byte sighash-typed sig) = 231.
 * p2wpkh: 41×4 + (1 + 1+72 + 1+33) = 272.  p2sh-p2wpkh: (41+23)×4 + 108 = 364.
 * These are upper bounds, so the real fee rate is never below the planned one.
 */
export const INPUT_WEIGHT = { p2tr: 231, p2wpkh: 272, p2sh: 364 };

export function outputWeight(script) { return (8 + compactSize(script.length).length + script.length) * 4; }

/** Upper-bound vsize for a tx with these input types and output scripts (version/locktime/counts/segwit marker). */
export function estimateVsize(inputTypes, outputScripts) {
  let w = (4 + 4) * 4 + 2; // version + locktime, segwit marker+flag (1 WU each)
  w += compactSize(inputTypes.length).length * 4 + compactSize(outputScripts.length).length * 4;
  for (const t of inputTypes) {
    const iw = INPUT_WEIGHT[t];
    if (!iw) throw new Error(`no size estimate for input type ${t}`);
    w += iw;
  }
  for (const s of outputScripts) w += outputWeight(s);
  return Math.ceil(w / 4);
}

export function inputTypeOfScript(script) {
  const t = scriptType(script);
  if (t === 'p2tr' || t === 'p2wpkh' || t === 'p2sh') return t;
  throw new Error(`unsupported input script type ${t}`);
}
