// lib/protobuf.js — the few protobuf messages `metashrew_view` takes and returns, hand-encoded.
//
// Schemas (alkanes-rs @ 52850a22):
//   crates/alkanes-support/proto/alkanes.proto:3-43,106-110
//     uint128 { uint64 lo = 1; uint64 hi = 2; }   AlkaneId { uint128 block = 1; uint128 tx = 2; }
//     AlkaneTransfer { AlkaneId id = 1; uint128 value = 2; }
//     MessageContextParcel { repeated AlkaneTransfer alkanes = 1; bytes transaction = 2; bytes block = 3;
//       uint64 height = 4; bytes calldata = 5; uint32 txindex = 6; uint32 vout = 7; uint32 pointer = 8;
//       uint32 refund_pointer = 9; }
//     ExtendedCallResponse { repeated AlkaneTransfer alkanes = 1; repeated KeyValuePair storage = 2; bytes data = 3; }
//     SimulateResponse { ExtendedCallResponse execution = 1; uint64 gas_used = 2; string error = 3; }
//   crates/protorune-support/proto/protorune.proto:10-53
//     OutpointWithProtocol { bytes txid = 1 (internal byte order); uint32 vout = 2; uint128 protocol = 3; }
//     OutpointResponse { BalanceSheet balances = 1; Outpoint outpoint = 2; Output output = 3; uint32 height = 4; ... }
//     BalanceSheet { repeated BalanceSheetItem entries = 1; }  BalanceSheetItem { Rune rune = 1; uint128 balance = 2; }
//     Rune { ProtoruneRuneId runeId = 1; ... }  ProtoruneRuneId { uint128 height = 1; uint128 txindex = 2; }
// Precedents: core crates/subfrost-fractal/src/frfb.rs:105-190 (simulate envelope; `error` checked FIRST — a revert is
// an HTTP 200 with empty data) and subfrost-app lib/alkanes/protorunesByOutpointMV.ts (txid little-endian; an empty
// "0x" answer means "no row", NOT "clean"; a non-empty answer must echo the outpoint asked for).
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { concat, hexToBytes, bytesToHex, reversed, fromUtf8 } from './bytes.js';

const U64 = (1n << 64n) - 1n;

export function pbVarint(v) {
  let x = BigInt(v);
  if (x < 0n) throw new Error('pb: negative varint');
  const out = [];
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x !== 0n) b |= 0x80;
    out.push(b);
  } while (x !== 0n);
  return Uint8Array.from(out);
}

const key = (field, wire) => pbVarint((field << 3) | wire);
const lenField = (field, bytes) => concat(key(field, 2), pbVarint(bytes.length), bytes);
const varField = (field, v) => concat(key(field, 0), pbVarint(v));

export function encUint128(v) {
  const x = BigInt(v);
  return concat(varField(1, x & U64), varField(2, x >> 64n));
}

export function encAlkaneTransfer({ id, value }) {
  const idMsg = concat(lenField(1, encUint128(id.block)), lenField(2, encUint128(id.tx)));
  return concat(lenField(1, idMsg), lenField(2, encUint128(value)));
}

/** MessageContextParcel for a simulate. `alkanes` are credited to the callee before the call (src/view.rs simulate_parcel). */
export function encodeSimulateParcel({ calldata, alkanes = [], height = 0, vout = 0, pointer = 0, refundPointer = 0, txindex = 0 }) {
  const parts = alkanes.map((t) => lenField(1, encAlkaneTransfer(t)));
  if (height) parts.push(varField(4, height));
  parts.push(lenField(5, calldata));
  if (txindex) parts.push(varField(6, txindex));
  if (vout) parts.push(varField(7, vout));
  if (pointer) parts.push(varField(8, pointer));
  if (refundPointer) parts.push(varField(9, refundPointer));
  return concat(...parts);
}

export function encodeOutpointWithProtocol(txidDisplayHex, vout, protocol = 1n) {
  const txid = reversed(hexToBytes(txidDisplayHex));
  if (txid.length !== 32) throw new Error('txid must be 32 bytes');
  return concat(lenField(1, txid), varField(2, vout), lenField(3, encUint128(protocol)));
}

/** Parse one message level → [{ field, wire, value }] (value: BigInt for varint, Uint8Array for bytes). Throws on truncation. */
export function pbFields(buf) {
  const out = [];
  let o = 0;
  const readVar = () => {
    let x = 0n, shift = 0n;
    for (let i = 0; i < 10; i++) {
      if (o >= buf.length) throw new Error('pb: truncated varint');
      const b = buf[o++];
      x |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return x;
      shift += 7n;
    }
    throw new Error('pb: varint too long');
  };
  while (o < buf.length) {
    const k = readVar();
    const field = Number(k >> 3n), wire = Number(k & 7n);
    if (wire === 0) out.push({ field, wire, value: readVar() });
    else if (wire === 2) {
      const n = Number(readVar());
      if (o + n > buf.length) throw new Error('pb: truncated bytes');
      out.push({ field, wire, value: buf.slice(o, o + n) });
      o += n;
    } else if (wire === 1) { if (o + 8 > buf.length) throw new Error('pb: truncated fixed64'); o += 8; }
    else if (wire === 5) { if (o + 4 > buf.length) throw new Error('pb: truncated fixed32'); o += 4; }
    else throw new Error(`pb: unsupported wire type ${wire}`);
  }
  return out;
}

function one(fields, f, wire) {
  const xs = fields.filter((x) => x.field === f);
  if (xs.length > 1) throw new Error(`pb: field ${f} repeated`);
  if (xs.length && xs[0].wire !== wire) throw new Error(`pb: field ${f} has wire type ${xs[0].wire}`);
  return xs.length ? xs[0].value : undefined;
}

export function decUint128(buf) {
  const f = pbFields(buf);
  const lo = one(f, 1, 0) ?? 0n, hi = one(f, 2, 0) ?? 0n;
  return (hi << 64n) | lo;
}

function decAlkaneId(buf) {
  const f = pbFields(buf);
  const b = one(f, 1, 2), t = one(f, 2, 2);
  return { block: b ? decUint128(b) : 0n, tx: t ? decUint128(t) : 0n };
}

function decAlkaneTransfer(buf) {
  const f = pbFields(buf);
  const id = one(f, 1, 2), v = one(f, 2, 2);
  return { id: id ? decAlkaneId(id) : { block: 0n, tx: 0n }, value: v ? decUint128(v) : 0n };
}

/** SimulateResponse → { error, data, alkanes, storage: Map(hexKey → Uint8Array), gasUsed }. */
export function decodeSimulateResponse(buf) {
  const top = pbFields(buf);
  const errBytes = one(top, 3, 2);
  const error = errBytes && errBytes.length ? fromUtf8(errBytes) : '';
  const exec = one(top, 1, 2);
  const gasUsed = one(top, 2, 0) ?? 0n;
  const res = { error, data: new Uint8Array(0), alkanes: [], storage: new Map(), gasUsed, hasExecution: !!exec };
  if (exec) {
    const ef = pbFields(exec);
    for (const x of ef) {
      if (x.field === 1 && x.wire === 2) res.alkanes.push(decAlkaneTransfer(x.value));
      else if (x.field === 2 && x.wire === 2) {
        const kv = pbFields(x.value);
        res.storage.set(bytesToHex(one(kv, 1, 2) || new Uint8Array(0)), one(kv, 2, 2) || new Uint8Array(0));
      } else if (x.field === 3 && x.wire === 2) res.data = x.value;
    }
  }
  return res;
}

/**
 * OutpointResponse → { empty: true } for the bare "no row" answer, else { empty: false, entries: [{id, amount}],
 * outpoint: { txid (display hex), vout } }. A non-empty answer without its balance sheet is another schema → throws.
 */
export function decodeOutpointResponse(buf) {
  if (buf.length === 0) return { empty: true, entries: [] };
  const top = pbFields(buf);
  const sheet = top.filter((x) => x.field === 1);
  if (sheet.length !== 1 || sheet[0].wire !== 2) throw new Error('OutpointResponse: no single balance sheet');
  const entries = [];
  for (const it of pbFields(sheet[0].value)) {
    if (it.field !== 1) continue;
    if (it.wire !== 2) throw new Error('BalanceSheet: bad entry wire type');
    const f = pbFields(it.value);
    const rune = one(f, 1, 2), bal = one(f, 2, 2);
    if (!rune) throw new Error('BalanceSheetItem: no rune');
    const rid = one(pbFields(rune), 1, 2);
    if (!rid) throw new Error('Rune: no id');
    const ridf = pbFields(rid);
    const h = one(ridf, 1, 2), t = one(ridf, 2, 2);
    entries.push({ id: { block: h ? decUint128(h) : 0n, tx: t ? decUint128(t) : 0n }, amount: bal ? decUint128(bal) : 0n });
  }
  const op = one(top, 2, 2);
  let outpoint;
  if (op) {
    const of = pbFields(op);
    const tx = one(of, 1, 2);
    outpoint = { txid: tx ? bytesToHex(reversed(tx)) : '', vout: Number(one(of, 2, 0) ?? 0n) };
  }
  return { empty: false, entries, outpoint };
}
