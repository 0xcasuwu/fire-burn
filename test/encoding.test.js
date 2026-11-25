// test/encoding.test.js — LEB128, 15-byte packing, cellpack, protostones, Runestone script. Each property has a
// poisoned twin that must fail for its own reason. Seeded PRNG: failures reproduce.
//
// Expected byte layouts are derived in-test from the alkanes-rs rules quoted in lib/alkanes.js (not pasted hex).
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  leb128, leb128Decode, leb128DecodeAll, leb128List, splitBytes15, joinBytes15, encodeCellpack, decodeCellpack,
  protostoneIntegers, encipherProtostones, decipherProtostones, runestoneScript, decodeRunestoneScript, shadowVout,
} from '../lib/alkanes.js';
import { bytesToHex, concat } from '../lib/bytes.js';

function prng(seed) { let x = seed >>> 0; return () => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x; }; }
const rnd = prng(0xf1e5);
const randU128 = () => { let v = 0n; const bits = rnd() % 129; for (let i = 0; i < bits; i++) v = (v << 1n) | BigInt(rnd() & 1); return v; };

test('LEB128 round-trips u128 incl. boundaries; decoder matches ord varint rules', () => {
  const vals = [0n, 1n, 127n, 128n, 16383n, 16384n, (1n << 64n) - 1n, 1n << 64n, (1n << 128n) - 1n];
  for (let i = 0; i < 500; i++) vals.push(randU128());
  for (const v of vals) {
    const b = leb128(v);
    const [d, n] = leb128Decode(b);
    assert.equal(d, v);
    assert.equal(n, b.length);
    // byte layout: little-endian 7-bit groups, high bit = continuation
    let back = 0n;
    b.forEach((x, i) => { back |= BigInt(x & 0x7f) << BigInt(7 * i); assert.equal((x & 0x80) !== 0, i < b.length - 1); });
    assert.equal(back, v);
  }
  assert.equal(leb128((1n << 128n) - 1n).length, 19);
});

test('LEB128 poisoned twins: unterminated, overlong, overflow, out of range', () => {
  assert.throws(() => leb128Decode(Uint8Array.of(0x80, 0x80)), /unterminated/);
  assert.throws(() => leb128Decode(new Uint8Array(20).fill(0x80)), /overlong/);
  const over = new Uint8Array(19).fill(0xff); over[18] = 0x04; // 2^128 → bit beyond u128
  assert.throws(() => leb128Decode(over), /overflow/);
  assert.throws(() => leb128(1n << 128n), /outside u128/);
  assert.throws(() => leb128(-1n), /outside u128/);
});

test('15-byte word packing: split/join round trip; the 16th byte is never used', () => {
  for (let i = 0; i < 200; i++) {
    const n = rnd() % 100;
    const b = Uint8Array.from({ length: n }, () => rnd() & 0xff);
    const words = splitBytes15(b);
    assert.equal(words.length, Math.ceil(n / 15));
    for (const w of words) assert.ok(w < 1n << 120n, 'word uses only 15 bytes');
    const j = joinBytes15(words);
    assert.deepEqual(j.slice(0, n), b);
    assert.ok(j.slice(n).every((x) => x === 0), 'padding is zeros');
  }
});

test('cellpack [2, 77623, 88] = LEB128 list; decode gives target + opcode', () => {
  const cp = encodeCellpack({ block: 2n, tx: 77623n }, [88n]);
  assert.deepEqual(cp, concat(leb128(2n), leb128(77623n), leb128(88n)));
  const d = decodeCellpack(cp);
  assert.equal(d.target.block, 2n); assert.equal(d.target.tx, 77623n); assert.deepEqual(d.inputs, [88n]);
  assert.throws(() => decodeCellpack(leb128(2n)), /fewer than two/); // poisoned twin
});

test('protostone integers follow to_integers order and delta-encode sorted edicts', () => {
  const ints = protostoneIntegers({
    pointer: 0, refund: 0, message: new Uint8Array(0),
    edicts: [{ id: { block: 2n, tx: 77623n }, amount: 5n, output: 5 }, { id: { block: 2n, tx: 7n }, amount: 1n, output: 0 }],
  });
  // ProtoPointer 91, Refund 93, then Body 0 with (2,7) then (0, 77623-7) deltas
  assert.deepEqual(ints, [91n, 0n, 93n, 0n, 0n, 2n, 7n, 1n, 0n, 0n, 77616n, 5n, 5n]);
  const withMsg = protostoneIntegers({ pointer: 1, refund: 2, message: encodeCellpack({ block: 2n, tx: 77623n }, [88n]), edicts: [] });
  assert.deepEqual(withMsg.slice(0, 4), [91n, 1n, 93n, 2n]);
  assert.equal(withMsg[4], 81n);
  assert.equal(withMsg.length, 6, 'a 5-byte cellpack fits one 15-byte word');
});

test('encipher → decipher round trip over random protostones', () => {
  for (let i = 0; i < 100; i++) {
    const stones = [];
    const k = 1 + (rnd() % 3);
    for (let s = 0; s < k; s++) {
      const edicts = [];
      const ne = rnd() % 3;
      for (let e = 0; e < ne; e++) edicts.push({ id: { block: BigInt(rnd() % 5), tx: BigInt(rnd() % 100000) }, amount: randU128() || 1n, output: rnd() % 10 });
      const msgLen = rnd() % 40;
      // a message's trailing zero bytes are padding on the wire; keep the last byte non-zero for exact compare
      const message = Uint8Array.from({ length: msgLen }, (_, j) => (j === msgLen - 1 ? 1 + (rnd() % 255) : rnd() & 0xff));
      stones.push({ protocolTag: 1n, pointer: rnd() % 6, refund: rnd() % 6, edicts, message });
    }
    const words = encipherProtostones(stones);
    const back = decipherProtostones(words);
    assert.equal(back.length, stones.length);
    back.forEach((b, s) => {
      assert.equal(b.protocolTag, 1n);
      assert.equal(b.pointer, BigInt(stones[s].pointer));
      assert.equal(b.refund, BigInt(stones[s].refund));
      assert.equal(bytesToHex(b.message).replace(/(00)+$/, ''), bytesToHex(stones[s].message).replace(/(00)+$/, ''));
      const want = [...stones[s].edicts].sort((x, y) => (x.id.block === y.id.block ? (x.id.tx < y.id.tx ? -1 : x.id.tx > y.id.tx ? 1 : 0) : x.id.block < y.id.block ? -1 : 1));
      assert.equal(b.edicts.length, want.length);
      b.edicts.forEach((e, j) => { assert.equal(e.id.block, want[j].id.block); assert.equal(e.id.tx, want[j].id.tx); assert.equal(e.amount, want[j].amount); assert.equal(e.output, BigInt(want[j].output)); });
      assert.equal(b.edictsMalformed, false);
    });
  }
});

test('decipher poisoned twins: edicts not in fours are flagged (the indexer silently drops them); short body throws', () => {
  // hand-build one stone whose body has 3 edict integers
  const values = [1n, 5n, 91n, 0n, 0n, 2n, 77623n, 10n];
  const words = splitBytes15(leb128List(values));
  const [s] = decipherProtostones(words);
  assert.equal(s.edictsMalformed, true);
  assert.equal(s.edicts.length, 0);
  // padding zeros of the last word decode as values too (as in Rust), so ask for more than a word can hold
  const short = splitBytes15(leb128List([1n, 30n, 91n, 0n]));
  assert.throws(() => decipherProtostones(short), /less values/);
});

test('Runestone script: OP_RETURN OP_13, pointer tag 22 then one 16383 per word; strict decode round trip', () => {
  const protocol = encipherProtostones([{ protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: encodeCellpack({ block: 2n, tx: 77623n }, [88n]) }]);
  const script = runestoneScript({ pointer: 0, protocol });
  assert.equal(script[0], 0x6a); assert.equal(script[1], 0x5d);
  const payload = leb128List([22n, 0n, ...protocol.flatMap((w) => [16383n, w])]);
  assert.deepEqual(script.slice(3), payload);
  assert.equal(script[2], payload.length);
  const d = decodeRunestoneScript(script, 3);
  assert.equal(d.pointer, 0n);
  assert.deepEqual(d.protocol, protocol);
  // long payloads split into ≤520-byte pushes and still decode
  const big = encipherProtostones([{ protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: new Uint8Array(700).fill(7) }]);
  const bs = runestoneScript({ pointer: 1, protocol: big });
  assert.deepEqual(decodeRunestoneScript(bs, 3).protocol, big);
});

test('Runestone decode poisoned twins: foreign tag, pointer ≥ outputs (cenotaph), non-push opcode, odd integer count', () => {
  const tag = (t, v) => concat(Uint8Array.of(0x6a, 0x5d), (() => { const p = leb128List([t, v]); return concat(Uint8Array.of(p.length), p); })());
  assert.throws(() => decodeRunestoneScript(tag(2n, 1n), 3), /unexpected tag 2/);
  assert.throws(() => decodeRunestoneScript(runestoneScript({ pointer: 3, protocol: [] }), 3), /pointer ≥ outputs/);
  assert.throws(() => decodeRunestoneScript(Uint8Array.of(0x6a, 0x5d, 0x51), 3), /non-push opcode/);
  const odd = leb128List([22n]);
  assert.throws(() => decodeRunestoneScript(concat(Uint8Array.of(0x6a, 0x5d, odd.length), odd), 3), /truncated field/);
  assert.throws(() => decodeRunestoneScript(Uint8Array.of(0x6a, 0x01, 0x00), 3), /not OP_RETURN OP_13/);
});

test('shadow vout = outputs + 1 + index (protorune lib.rs:1023)', () => {
  assert.equal(shadowVout(3, 0), 4);
  assert.equal(shadowVout(3, 1), 5);
  assert.equal(shadowVout(2, 1), 4);
});

test('LEB decodeAll consumes exactly', () => {
  const v = [1n, 300n, 77623n];
  assert.deepEqual(leb128DecodeAll(leb128List(v)), v);
});
