// lib/alkanes.js — LEB128, cellpack, protostone and Runestone (tag 16383) encode + decode.
//
// PURPOSE: byte-exact re-implementation of the alkanes-rs encoders this page needs, and a STRICT decoder used
// to re-read the transaction we built before the wallet prompt (gate 4). Every function cites the Rust it mirrors
// (alkanes-rs @ 52850a22):
//   - LEB128 varint ............ crates/ordinals/src/varint.rs:11-33 (decode: ≤19 bytes, byte 19 ≤ 2 bits)
//   - Runestone payload ........ crates/ordinals/src/runestone.rs:144-222 (Pointer tag 22, then one Protocol
//                                tag 16383 per u128, script = OP_RETURN OP_13 <pushes of ≤520 bytes>)
//   - Runestone pointer rule ... runestone.rs:103-107 (pointer must be < outputs.len(), else the even tag 22 is
//                                left over → UnrecognizedEvenTag → cenotaph)
//   - protostone integers ...... crates/protorune-support/src/protostone.rs:222-263 (`to_integers`: Burn 83,
//                                ProtoPointer 91, Refund 93, From 95, Message 81 per 15-byte chunk, Body 0 edicts
//                                sorted by id, delta-encoded)
//   - protostones encipher ..... crates/protorune/src/protostone.rs:225-235 ([tag, len, ...ints]* → LEB128 →
//                                split into 15-byte little-endian u128 words, `split_bytes` protostone.rs:180-197)
//   - protostones decipher ..... protostone.rs:300-332 (`join_to_bytes` snaps each word to 15 bytes; a 0 tag ends;
//                                `to_fields` protostone.rs:126-145: key 0 swallows the rest as the edict body)
//   - edict body ............... protostone.rs:60-84: sets of four, else the edicts are SILENTLY dropped
//                                (`from_fields_and_tag` .and_then(|v| v.ok()).unwrap_or_else(vec![])) — our decoder
//                                flags that case instead of hiding it.
//   - cellpack ................. crates/alkanes-support/src/cellpack.rs:28-46 (LEB128 of [block, tx, ...inputs])
//
// DECODER STRICTNESS (our choice, safer than the indexer): `decodeRunestoneScript` refuses any tag other than
// Pointer(22) and Protocol(16383), any non-push opcode, any varint error and an odd integer count. The page only
// ever decodes the transaction it built, so anything else means the builder (or a wallet) changed it.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { concat, leToBigInt, bigIntToLe } from './bytes.js';

export const TAG_BODY = 0n;
export const TAG_POINTER = 22n;
export const TAG_PROTOCOL = 16383n;
export const PS_BURN = 83n;
export const PS_MESSAGE = 81n;
export const PS_REFUND = 93n;
export const PS_POINTER = 91n;
export const PS_FROM = 95n;
export const ALKANES_PROTOCOL_TAG = 1n;

const U128_MAX = (1n << 128n) - 1n;

// ── LEB128 ────────────────────────────────────────────────────────────────────

export function leb128(value) {
  let v = BigInt(value);
  if (v < 0n || v > U128_MAX) throw new Error('leb128: value outside u128');
  const out = [];
  for (;;) {
    const byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v === 0n) { out.push(byte); return Uint8Array.from(out); }
    out.push(byte | 0x80);
  }
}

export function leb128List(values) { return concat(...values.map(leb128)); }

/** Decode one varint at `offset` → [value, bytesRead]. Mirrors ordinals varint.rs:11-33. */
export function leb128Decode(buf, offset = 0) {
  let n = 0n;
  for (let i = 0; offset + i < buf.length; i++) {
    if (i > 18) throw new Error('varint overlong');
    const byte = buf[offset + i];
    const value = BigInt(byte & 0x7f);
    if (i === 18 && (value & 0x7cn) !== 0n) throw new Error('varint overflow');
    n |= value << BigInt(7 * i);
    if ((byte & 0x80) === 0) return [n, i + 1];
  }
  throw new Error('varint unterminated');
}

export function leb128DecodeAll(buf) {
  const out = [];
  let o = 0;
  while (o < buf.length) { const [v, n] = leb128Decode(buf, o); out.push(v); o += n; }
  return out;
}

// ── 15-byte word packing (protostone.rs split_bytes / join_to_bytes) ─────────

export function splitBytes15(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i += 15) {
    const chunk = new Uint8Array(16);
    chunk.set(bytes.slice(i, i + 15));
    words.push(leToBigInt(chunk));
  }
  return words;
}

export function joinBytes15(words) {
  return concat(...words.map((w) => bigIntToLe(w, 16).slice(0, 15)));
}

// ── cellpack ─────────────────────────────────────────────────────────────────

export function encodeCellpack(target, inputs) {
  return leb128List([BigInt(target.block), BigInt(target.tx), ...inputs.map(BigInt)]);
}

/** calldata → { target, inputs } (alkanes decode_varint_list + Cellpack::try_from, needs ≥ 2 values). */
export function decodeCellpack(calldata) {
  const list = leb128DecodeAll(calldata);
  if (list.length < 2) throw new Error('cellpack: fewer than two values');
  return { target: { block: list[0], tx: list[1] }, inputs: list.slice(2) };
}

// ── protostones ──────────────────────────────────────────────────────────────

function cmpId(a, b) {
  if (a.block !== b.block) return a.block < b.block ? -1 : 1;
  if (a.tx !== b.tx) return a.tx < b.tx ? -1 : 1;
  return 0;
}

/** protostone.rs `to_integers`. Fields: { burn?, pointer?, refund?, from?, message: Uint8Array, edicts: [{id:{block,tx}, amount, output}] } */
export function protostoneIntegers(ps) {
  const out = [];
  if (ps.burn !== undefined && ps.burn !== null) out.push(PS_BURN, BigInt(ps.burn));
  if (ps.pointer !== undefined && ps.pointer !== null) out.push(PS_POINTER, BigInt(ps.pointer));
  if (ps.refund !== undefined && ps.refund !== null) out.push(PS_REFUND, BigInt(ps.refund));
  if (ps.from !== undefined && ps.from !== null) out.push(PS_FROM, BigInt(ps.from));
  if (ps.message && ps.message.length) for (const w of splitBytes15(ps.message)) out.push(PS_MESSAGE, w);
  if (ps.edicts && ps.edicts.length) {
    out.push(TAG_BODY);
    const edicts = ps.edicts.map((e) => ({
      id: { block: BigInt(e.id.block), tx: BigInt(e.id.tx) }, amount: BigInt(e.amount), output: BigInt(e.output),
    })).sort((a, b) => cmpId(a.id, b.id));
    let prev = { block: 0n, tx: 0n };
    for (const e of edicts) {
      const db = e.id.block - prev.block;
      const dt = db === 0n ? e.id.tx - prev.tx : e.id.tx;
      if (db < 0n || dt < 0n) throw new Error('edict delta underflow');
      out.push(db, dt, e.amount, e.output);
      prev = e.id;
    }
  }
  return out;
}

/** protorune protostone.rs:225-235 `encipher` → the u128 words carried under tag 16383. */
export function encipherProtostones(stones) {
  const values = [];
  for (const s of stones) {
    const ints = protostoneIntegers(s);
    values.push(BigInt(s.protocolTag ?? ALKANES_PROTOCOL_TAG), BigInt(ints.length), ...ints);
  }
  return splitBytes15(leb128List(values));
}

function toFields(values) {
  const map = new Map();
  let i = 0;
  while (i + 1 < values.length) {
    const key = values[i], value = values[i + 1];
    i += 2;
    if (key === 0n) {
      map.set(0n, [...(map.get(0n) || []), value, ...values.slice(i)]);
      break;
    }
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
  }
  return map;
}

function edictsFromIntegers(list) {
  if (list.length % 4 !== 0) return null; // the indexer drops ALL edicts in this case
  const out = [];
  let last = { block: 0n, tx: 0n };
  for (let i = 0; i < list.length; i += 4) {
    const [b, t, amount, output] = list.slice(i, i + 4);
    const id = { block: last.block + b, tx: b === 0n ? last.tx + t : t };
    out.push({ id, amount, output });
    last = id;
  }
  return out;
}

/** protostone.rs:300-332 `decipher` → [{ protocolTag, burn, pointer, refund, from, message, edicts, edictsMalformed, unknownKeys }] */
export function decipherProtostones(words) {
  const raw = joinBytes15(words);
  const ints = leb128DecodeAll(raw);
  const out = [];
  let i = 0;
  for (;;) {
    if (i >= ints.length) break;
    const tag = ints[i++];
    if (tag === 0n) break;
    if (i >= ints.length) break;
    const length = Number(ints[i++]);
    if (i + length > ints.length) throw new Error('protostone: less values than expected');
    const body = ints.slice(i, i + length);
    i += length;
    const f = toFields(body);
    const one = (k) => (f.has(k) ? f.get(k)[0] : undefined);
    const edictInts = f.get(0n);
    const edicts = edictInts ? edictsFromIntegers(edictInts) : [];
    const known = new Set([PS_BURN, PS_MESSAGE, PS_REFUND, PS_POINTER, PS_FROM, 0n]);
    out.push({
      protocolTag: tag,
      burn: one(PS_BURN),
      pointer: one(PS_POINTER),
      refund: one(PS_REFUND),
      from: one(PS_FROM),
      message: f.has(PS_MESSAGE) ? joinBytes15(f.get(PS_MESSAGE)) : new Uint8Array(0),
      edicts: edicts || [],
      edictsMalformed: edicts === null,
      unknownKeys: [...f.keys()].filter((k) => !known.has(k)),
      repeatedKeys: [...f.entries()].filter(([k, v]) => k !== 0n && k !== PS_MESSAGE && v.length > 1).map(([k]) => k),
    });
  }
  return out;
}

// ── Runestone script ─────────────────────────────────────────────────────────

const OP_RETURN = 0x6a;
const OP_13 = 0x5d;

function pushData(data) {
  const n = data.length;
  if (n < 0x4c) return concat(Uint8Array.of(n), data);
  if (n <= 0xff) return concat(Uint8Array.of(0x4c, n), data);
  if (n <= 0xffff) return concat(Uint8Array.of(0x4d, n & 0xff, n >> 8), data);
  throw new Error('push too large');
}

/** runestone.rs:144-222 for a Runestone that carries only `pointer` and `protocol`. */
export function runestoneScript({ pointer, protocol }) {
  const ints = [];
  if (pointer !== undefined && pointer !== null) ints.push(TAG_POINTER, BigInt(pointer));
  for (const w of protocol || []) ints.push(TAG_PROTOCOL, w);
  const payload = leb128List(ints);
  const parts = [Uint8Array.of(OP_RETURN, OP_13)];
  for (let i = 0; i < payload.length; i += 520) parts.push(pushData(payload.slice(i, i + 520)));
  if (payload.length === 0) parts.push(Uint8Array.of(0));
  return concat(...parts);
}

export function isOpReturn(script) { return script.length > 0 && script[0] === OP_RETURN; }

/** Strict decode of OUR runestone. Returns { pointer, protocol } or throws with the reason. */
export function decodeRunestoneScript(script, numOutputs) {
  if (script[0] !== OP_RETURN || script[1] !== OP_13) throw new Error('runestone: not OP_RETURN OP_13');
  let o = 2;
  const chunks = [];
  while (o < script.length) {
    const op = script[o++];
    let n;
    if (op <= 0x4b) n = op;
    else if (op === 0x4c) { n = script[o]; o += 1; }
    else if (op === 0x4d) { n = script[o] | (script[o + 1] << 8); o += 2; }
    else if (op === 0x4e) { n = (script[o] | (script[o + 1] << 8) | (script[o + 2] << 16) | (script[o + 3] << 24)) >>> 0; o += 4; }
    else throw new Error(`runestone: non-push opcode 0x${op.toString(16)}`);
    if (n === undefined || o + n > script.length) throw new Error('runestone: truncated push');
    chunks.push(script.slice(o, o + n));
    o += n;
  }
  const ints = leb128DecodeAll(concat(...chunks));
  if (ints.length % 2 !== 0) throw new Error('runestone: truncated field');
  let pointer;
  const protocol = [];
  for (let i = 0; i < ints.length; i += 2) {
    const tag = ints[i], value = ints[i + 1];
    if (tag === TAG_POINTER) {
      if (pointer !== undefined) throw new Error('runestone: pointer repeated');
      pointer = value;
    } else if (tag === TAG_PROTOCOL) protocol.push(value);
    else throw new Error(`runestone: unexpected tag ${tag}`);
  }
  if (pointer !== undefined && numOutputs !== undefined && pointer >= BigInt(numOutputs)) {
    throw new Error('runestone: pointer ≥ outputs (cenotaph)');
  }
  return { pointer, protocol };
}

/** The shadow (virtual) vout of protostone i: crates/protorune/src/lib.rs:1023 (i + tx.output.len() + 1). */
export function shadowVout(numOutputs, i) { return numOutputs + 1 + i; }
