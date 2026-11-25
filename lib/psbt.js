// lib/psbt.js — BIP174 (PSBT v0) create / parse / finalize / extract, for the three input kinds the page spends.
//
// WHAT WE WRITE per input (BIP174 key types):
//   0x01 WITNESS_UTXO (value + scriptPubKey) — every input (all are segwit: p2tr, p2wpkh, p2sh-p2wpkh)
//   0x17 TAP_INTERNAL_KEY (32-byte x-only)   — p2tr inputs (wallets refuse a taproot input without it; app
//                                              CLAUDE.md "tapInternalKey Patching — DO NOT REMOVE")
//   0x04 REDEEM_SCRIPT (0x0014‖hash160(pk))  — p2sh-p2wpkh inputs (Xverse's default payment account; app
//                                              lib/wallet/browserWalletSigning.ts injectRedeemScripts)
// No sighash type is written: taproot signs SIGHASH_DEFAULT, segwit v0 SIGHASH_ALL — both commit to every input
// and output, so no wallet can be asked to sign a partial transaction.
//
// WHAT WE READ BACK: a wallet may return the PSBT signed but not finalized (Xverse, OYL with finalize:false),
// finalized (UniSat autoFinalized, SUBFROST connect self-finalizes), or a raw tx. `extractSigned` accepts all
// three and returns a transaction; the caller then requires its txid to equal the one we built.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { Reader, bytesToBase64, base64ToBytes, bytesToHex, compactSize, concat, hexToBytes, u64le } from './bytes.js';
import { parseTx, serializeTx } from './tx.js';
import { scriptType } from './address.js';

const MAGIC = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff);

function kv(key, value) { return concat(compactSize(key.length), key, compactSize(value.length), value); }

/** inputsMeta[i] = { witnessUtxo: { value: BigInt, script }, tapInternalKey?: Uint8Array(32), redeemScript?: Uint8Array } */
export function createPsbt(tx, inputsMeta) {
  if (inputsMeta.length !== tx.inputs.length) throw new Error('psbt: meta/input count mismatch');
  const unsigned = { ...tx, inputs: tx.inputs.map((i) => ({ ...i, scriptSig: new Uint8Array(0), witness: [] })) };
  const parts = [MAGIC, kv(Uint8Array.of(0x00), serializeTx(unsigned, { witness: false })), Uint8Array.of(0x00)];
  for (const m of inputsMeta) {
    const s = m.witnessUtxo.script;
    parts.push(kv(Uint8Array.of(0x01), concat(u64le(m.witnessUtxo.value), compactSize(s.length), s)));
    if (m.redeemScript) parts.push(kv(Uint8Array.of(0x04), m.redeemScript));
    if (m.tapInternalKey) {
      if (m.tapInternalKey.length !== 32) throw new Error('psbt: tapInternalKey must be 32 bytes');
      parts.push(kv(Uint8Array.of(0x17), m.tapInternalKey));
    }
    for (const x of m.extra || []) parts.push(kv(x.key, x.value)); // tests only: simulate what a wallet adds
    parts.push(Uint8Array.of(0x00));
  }
  for (let k = 0; k < tx.outputs.length; k++) parts.push(Uint8Array.of(0x00));
  return concat(...parts);
}

function readMap(r) {
  const entries = [];
  for (;;) {
    const klen = r.compactSize();
    if (klen === 0) return entries;
    const key = r.bytes(klen);
    const value = r.varBytes();
    entries.push({ type: key[0], keydata: key.slice(1), value });
  }
}

export function parsePsbt(bytes) {
  const r = new Reader(bytes);
  const magic = r.bytes(5);
  for (let i = 0; i < 5; i++) if (magic[i] !== MAGIC[i]) throw new Error('psbt: bad magic');
  const global = readMap(r);
  const txEntry = global.find((e) => e.type === 0x00 && e.keydata.length === 0);
  if (!txEntry) throw new Error('psbt: no unsigned tx');
  const tx = parseTx(txEntry.value);
  const inputs = tx.inputs.map(() => {
    const m = readMap(r);
    const one = (t) => { const e = m.find((x) => x.type === t && x.keydata.length === 0); return e ? e.value : undefined; };
    const wu = one(0x01);
    let witnessUtxo;
    if (wu) { const rr = new Reader(wu); witnessUtxo = { value: rr.u64(), script: rr.varBytes() }; }
    let finalScriptWitness;
    const fw = one(0x08);
    if (fw) { const rr = new Reader(fw); const n = rr.compactSize(); finalScriptWitness = []; for (let k = 0; k < n; k++) finalScriptWitness.push(rr.varBytes()); }
    return {
      raw: m,
      witnessUtxo,
      redeemScript: one(0x04),
      finalScriptSig: one(0x07),
      finalScriptWitness,
      tapKeySig: one(0x13),
      tapInternalKey: one(0x17),
      partialSigs: m.filter((x) => x.type === 0x02).map((x) => ({ pubkey: x.keydata, sig: x.value })),
    };
  });
  const outputs = tx.outputs.map(() => readMap(r));
  return { tx, inputs, outputs };
}

function pushOnly(data) {
  if (data.length >= 0x4c) throw new Error('psbt: redeemScript too long for this finalizer');
  return concat(Uint8Array.of(data.length), data);
}

/** Finalize each input from what the wallet returned, then return the network transaction. */
export function finalizeAndExtract(parsed) {
  const tx = { ...parsed.tx, inputs: parsed.tx.inputs.map((i) => ({ ...i })) };
  parsed.inputs.forEach((inp, idx) => {
    const t = tx.inputs[idx];
    if (inp.finalScriptWitness) {
      t.witness = inp.finalScriptWitness;
      t.scriptSig = inp.finalScriptSig || new Uint8Array(0);
      return;
    }
    const spk = inp.witnessUtxo ? inp.witnessUtxo.script : null;
    if (!spk) throw new Error(`input ${idx}: no witnessUtxo, cannot finalize`);
    const kind = scriptType(spk);
    if (kind === 'p2tr') {
      if (!inp.tapKeySig) throw new Error(`input ${idx}: taproot input not signed`);
      if (inp.tapKeySig.length !== 64 && inp.tapKeySig.length !== 65) throw new Error(`input ${idx}: bad schnorr signature length`);
      t.witness = [inp.tapKeySig];
      t.scriptSig = new Uint8Array(0);
    } else if (kind === 'p2wpkh' || kind === 'p2sh') {
      if (inp.partialSigs.length !== 1) throw new Error(`input ${idx}: expected one signature, got ${inp.partialSigs.length}`);
      const { pubkey, sig } = inp.partialSigs[0];
      t.witness = [sig, pubkey];
      if (kind === 'p2sh') {
        if (!inp.redeemScript) throw new Error(`input ${idx}: p2sh input without redeemScript`);
        t.scriptSig = pushOnly(inp.redeemScript);
      } else t.scriptSig = new Uint8Array(0);
    } else throw new Error(`input ${idx}: unsupported script type ${kind}`);
  });
  return tx;
}

/** Wallet answer (PSBT hex | PSBT base64 | raw tx hex | bytes) → finalized transaction. */
export function extractSigned(answer) {
  let bytes;
  if (answer instanceof Uint8Array) bytes = answer;
  else if (typeof answer === 'string') {
    const s = answer.trim();
    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) bytes = hexToBytes(s);
    else bytes = base64ToBytes(s);
  } else throw new Error('wallet returned no signed data');
  if (bytes.length >= 5 && bytes[0] === 0x70 && bytes[1] === 0x73 && bytes[2] === 0x62 && bytes[3] === 0x74 && bytes[4] === 0xff) {
    return finalizeAndExtract(parsePsbt(bytes));
  }
  return parseTx(bytes);
}

export const psbtToHex = (b) => bytesToHex(b);
export const psbtToBase64 = (b) => bytesToBase64(b);
