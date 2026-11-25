// test/psbt.test.js — transaction serialization, txid, size estimates, and BIP174 create/parse/finalize/extract for
// the three input kinds, plus every wallet answer shape (PSBT hex, PSBT base64, finalized PSBT, raw tx).
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { serializeTx, parseTx, txid, vsize, weight, estimateVsize } from '../lib/tx.js';
import { createPsbt, parsePsbt, finalizeAndExtract, extractSigned } from '../lib/psbt.js';
import { bytesToHex, bytesToBase64, concat, reversed } from '../lib/bytes.js';
import { hash160 } from '../lib/ripemd160.js';

const rb = (n) => new Uint8Array(randomBytes(n));
const p2tr = () => concat(Uint8Array.of(0x51, 0x20), rb(32));
const p2wpkh = (pk) => concat(Uint8Array.of(0x00, 0x14), hash160(pk));
const p2shOf = (redeem) => concat(Uint8Array.of(0xa9, 0x14), hash160(redeem), Uint8Array.of(0x87));

function randTx(nIn = 3, nOut = 3, witness = true) {
  return {
    version: 2, locktime: 0,
    inputs: Array.from({ length: nIn }, (_, i) => ({ txid: bytesToHex(rb(32)), vout: i, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: witness ? [rb(64)] : [] })),
    outputs: Array.from({ length: nOut }, () => ({ value: BigInt(1 + (randomBytes(4).readUInt32LE() % 1e8)), script: p2tr() })),
  };
}

test('tx serialize ⇄ parse round trip; txid = reversed sha256d of the non-witness serialization', () => {
  for (let k = 0; k < 30; k++) {
    const tx = randTx(1 + (k % 4), 1 + (k % 3), k % 2 === 0);
    const b = serializeTx(tx);
    const back = parseTx(b);
    assert.equal(bytesToHex(serializeTx(back)), bytesToHex(b));
    const nw = serializeTx(tx, { witness: false });
    const d = createHash('sha256').update(createHash('sha256').update(nw).digest()).digest();
    assert.equal(txid(tx), bytesToHex(reversed(d)));
    assert.equal(weight(tx), nw.length * 3 + b.length);
  }
  assert.throws(() => parseTx(concat(serializeTx(randTx()), Uint8Array.of(0))), /trailing/); // poisoned twin
});

test('estimateVsize upper-bounds the finalized size for each input kind (and stays within 2 vB per input)', () => {
  const pk = concat(Uint8Array.of(2), rb(32));
  const redeem = concat(Uint8Array.of(0, 0x14), hash160(pk));
  const kinds = [
    ['p2tr', () => ({ scriptSig: new Uint8Array(0), witness: [rb(64)] })],
    ['p2wpkh', () => ({ scriptSig: new Uint8Array(0), witness: [rb(72), pk] })],
    ['p2sh', () => ({ scriptSig: concat(Uint8Array.of(redeem.length), redeem), witness: [rb(72), pk] })],
  ];
  for (const [kind, fin] of kinds) {
    for (const n of [1, 2, 5]) {
      const outs = [p2tr(), p2wpkh(pk), concat(Uint8Array.of(0x6a, 0x5d, 40), rb(40))];
      const tx = { version: 2, locktime: 0, outputs: outs.map((s) => ({ value: 1000n, script: s })),
        inputs: Array.from({ length: n }, (_, i) => ({ txid: bytesToHex(rb(32)), vout: i, sequence: 0, ...fin() })) };
      const est = estimateVsize(Array(n).fill(kind), outs);
      const real = vsize(tx);
      assert.ok(est >= real, `${kind}×${n}: estimate ${est} < real ${real}`);
      assert.ok(est - real <= 2 * n + 1, `${kind}×${n}: estimate ${est} too loose vs ${real}`);
    }
  }
  assert.throws(() => estimateVsize(['p2pkh'], []), /no size estimate/);
});

function psbtFixture() {
  const pk = concat(Uint8Array.of(3), rb(32));
  const redeem = concat(Uint8Array.of(0, 0x14), hash160(pk));
  const tx = randTx(3, 2, false);
  const metas = [
    { witnessUtxo: { value: 546n, script: p2tr() }, tapInternalKey: rb(32) },
    { witnessUtxo: { value: 9000n, script: p2wpkh(pk) } },
    { witnessUtxo: { value: 7000n, script: p2shOf(redeem) }, redeemScript: redeem },
  ];
  return { tx, metas, pk, redeem };
}

test('createPsbt ⇄ parsePsbt: unsigned tx, witnessUtxo, tapInternalKey, redeemScript survive; scriptSigs cleared', () => {
  const { tx, metas, redeem } = psbtFixture();
  tx.inputs[2].scriptSig = concat(Uint8Array.of(redeem.length), redeem); // the planned final scriptSig
  const b = createPsbt(tx, metas);
  assert.deepEqual([...b.slice(0, 5)], [0x70, 0x73, 0x62, 0x74, 0xff]);
  const p = parsePsbt(b);
  assert.ok(p.tx.inputs.every((i) => i.scriptSig.length === 0 && i.witness.length === 0), 'PSBT unsigned tx has empty scriptSigs');
  p.inputs.forEach((inp, i) => {
    assert.equal(inp.witnessUtxo.value, metas[i].witnessUtxo.value);
    assert.equal(bytesToHex(inp.witnessUtxo.script), bytesToHex(metas[i].witnessUtxo.script));
  });
  assert.equal(bytesToHex(p.inputs[0].tapInternalKey), bytesToHex(metas[0].tapInternalKey));
  assert.equal(bytesToHex(p.inputs[2].redeemScript), bytesToHex(redeem));
  assert.equal(p.outputs.length, 2);
  assert.throws(() => createPsbt(tx, metas.slice(1)), /count mismatch/);
  assert.throws(() => parsePsbt(concat(Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0x00), b.slice(5))), /bad magic/);
});

test('finalize: tapKeySig → [sig]; p2wpkh → [sig, pk]; p2sh-p2wpkh → push(redeem) + [sig, pk]; the txid includes the p2sh scriptSig', () => {
  const { tx, metas, pk, redeem } = psbtFixture();
  const sig = rb(64), s1 = rb(71), s2 = rb(72);
  const signed = createPsbt(tx, [
    { ...metas[0], extra: [{ key: Uint8Array.of(0x13), value: sig }] },
    { ...metas[1], extra: [{ key: concat(Uint8Array.of(0x02), pk), value: s1 }] },
    { ...metas[2], extra: [{ key: concat(Uint8Array.of(0x02), pk), value: s2 }] },
  ]);
  const out = finalizeAndExtract(parsePsbt(signed));
  assert.deepEqual(out.inputs[0].witness.map(bytesToHex), [bytesToHex(sig)]);
  assert.deepEqual(out.inputs[1].witness.map(bytesToHex), [bytesToHex(s1), bytesToHex(pk)]);
  assert.equal(bytesToHex(out.inputs[2].scriptSig), bytesToHex(concat(Uint8Array.of(22), redeem)));
  const planned = { ...tx, inputs: tx.inputs.map((i, k) => (k === 2 ? { ...i, scriptSig: concat(Uint8Array.of(22), redeem) } : i)) };
  assert.equal(txid(out), txid(planned));
  assert.notEqual(txid(out), txid(tx), 'poisoned twin: planning with an empty p2sh scriptSig gives another txid');
  // the same answer as hex, base64, and the extracted raw tx
  assert.equal(txid(extractSigned(bytesToHex(signed))), txid(out));
  assert.equal(txid(extractSigned(bytesToBase64(signed))), txid(out));
  assert.equal(txid(extractSigned(bytesToHex(serializeTx(out)))), txid(out));
});

test('finalized PSBT (finalScriptWitness) is taken as is', () => {
  const { tx, metas } = psbtFixture();
  const w = [rb(64)];
  const enc = concat(Uint8Array.of(1, 64), w[0]);
  const b = createPsbt({ ...tx, inputs: tx.inputs.slice(0, 1) }, [{ ...metas[0], extra: [{ key: Uint8Array.of(0x08), value: enc }] }]);
  const out = extractSigned(b);
  assert.equal(bytesToHex(out.inputs[0].witness[0]), bytesToHex(w[0]));
});

test('finalize poisoned twins: unsigned taproot, bad sig length, two signatures, no witnessUtxo, garbage answer', () => {
  const { tx, metas, pk } = psbtFixture();
  const only = (m) => createPsbt({ ...tx, inputs: tx.inputs.slice(0, 1) }, [m]);
  assert.throws(() => extractSigned(only(metas[0])), /not signed/);
  assert.throws(() => extractSigned(only({ ...metas[0], extra: [{ key: Uint8Array.of(0x13), value: rb(63) }] })), /signature length/);
  assert.throws(() => extractSigned(only({ ...metas[1], extra: [
    { key: concat(Uint8Array.of(2), pk), value: rb(71) }, { key: concat(Uint8Array.of(2), concat(Uint8Array.of(2), rb(32))), value: rb(71) },
  ] })), /expected one signature/);
  assert.throws(() => extractSigned(only({ witnessUtxo: undefined, extra: [] })), /./);
  assert.throws(() => extractSigned('not a psbt at all!'), /./);
  assert.throws(() => extractSigned(undefined), /no signed data/);
});
