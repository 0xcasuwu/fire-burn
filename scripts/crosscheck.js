// scripts/crosscheck.js — independent cross-check of the runestone/protostone encoder and decoder.
//
//   node scripts/crosscheck.js                 synthetic burn runestones → ~/.claude/skills/alkanes-local-decode
//                                              decode_protostone.py (python3 -I) must yield the same pointer,
//                                              refund, edicts and cellpack as lib/alkanes.js
//   node scripts/crosscheck.js --golden TXID   fetch a mainnet tx (read-only, tlsfetch-curl), decode its OP_RETURN
//                                              with both decoders, then RE-ENCODE our decode and require the exact
//                                              on-chain bytes; with --save writes test/fixtures/<txid>.hex
//
// The decoder skill is a separate hand implementation of the same alkanes-rs rules (its SKILL.md: "byte-verified
// against alkanes-rs source"), so agreement is evidence neither side mis-reads the format.
// JOURNAL 2026-11-25 created for fire-burn.

import { execFileSync } from 'node:child_process';
import { writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encipherProtostones, runestoneScript, decodeRunestoneScript, decipherProtostones, decodeCellpack, encodeCellpack, isOpReturn } from '../lib/alkanes.js';
import { bytesToHex, hexToBytes } from '../lib/bytes.js';
import { parseTx } from '../lib/tx.js';
import { makeRpc } from '../lib/chain.js';
import { tlsfetchTransport } from './tlsfetch-transport.js';
import { RPC_URL } from '../lib/config.js';

export const DECODER = process.env.ALKANES_DECODER || join(homedir(), '.claude/skills/alkanes-local-decode/lib/decode_protostone.py');

export function pythonDecode(scriptHex) {
  const text = execFileSync('python3', ['-I', DECODER, scriptHex], { encoding: 'utf8' });
  // keep integers above 2^53 exact: quote every long digit run before JSON.parse
  return JSON.parse(text.replace(/([:\[,\s])(\d{16,})(?=[,\]}\s])/g, '$1"$2"'));
}

/** Compare our decode with the Python decoder's JSON; returns a list of mismatches (empty = agree). */
export function compare(scriptBytes, numOutputs) {
  const ours = decodeRunestoneScript(scriptBytes, numOutputs);
  const stones = decipherProtostones(ours.protocol);
  const py = pythonDecode(bytesToHex(scriptBytes));
  const bad = [];
  if (py.cenotaph) bad.push('python says cenotaph');
  if (BigInt(py.pointer ?? -1) !== (ours.pointer ?? -1n)) bad.push(`pointer ${py.pointer} vs ${ours.pointer}`);
  if (py.protostones.length !== stones.length) bad.push(`stone count ${py.protostones.length} vs ${stones.length}`);
  stones.forEach((s, i) => {
    const p = py.protostones[i] || {};
    if (BigInt(p.protocol_tag) !== s.protocolTag) bad.push(`p${i} tag`);
    if (BigInt(p.pointer ?? -1) !== (s.pointer ?? -1n)) bad.push(`p${i} pointer ${p.pointer} vs ${s.pointer}`);
    if (BigInt(p.refund ?? -1) !== (s.refund ?? -1n)) bad.push(`p${i} refund ${p.refund} vs ${s.refund}`);
    const pe = p.edicts || [];
    if (pe.length !== s.edicts.length) bad.push(`p${i} edict count ${pe.length} vs ${s.edicts.length}`);
    pe.forEach((e, j) => {
      const o = s.edicts[j];
      if (!o || BigInt(e.id[0]) !== o.id.block || BigInt(e.id[1]) !== o.id.tx || BigInt(e.amount) !== o.amount || BigInt(e.output) !== o.output) bad.push(`p${i} edict ${j}`);
    });
    if (s.message.length) {
      const cp = decodeCellpack(s.message);
      const pc = p.cellpack;
      if (!pc) bad.push(`p${i} python has no cellpack`);
      else {
        if (BigInt(pc.target.block) !== cp.target.block || BigInt(pc.target.tx) !== cp.target.tx) bad.push(`p${i} target`);
        if (pc.inputs.length !== cp.inputs.length || pc.inputs.some((v, k) => BigInt(v) !== cp.inputs[k])) bad.push(`p${i} inputs`);
      }
    } else if (p.cellpack) bad.push(`p${i} python sees a cellpack we do not`);
  });
  return { bad, ours, stones, py };
}

export function burnScript(amount, numOutputs) {
  const FIRE = { block: 2n, tx: 77623n };
  return runestoneScript({ pointer: 0, protocol: encipherProtostones([
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [{ id: FIRE, amount, output: numOutputs + 2 }], message: new Uint8Array(0) },
    { protocolTag: 1n, pointer: 0, refund: 0, edicts: [], message: encodeCellpack(FIRE, [88n]) },
  ]) });
}

/** Re-encode a decoded runestone; returns the bytes (to compare with the on-chain script). */
export function reencode(ours, stones) {
  return runestoneScript({ pointer: ours.pointer, protocol: encipherProtostones(stones.map((s) => ({
    protocolTag: s.protocolTag, burn: s.burn, pointer: s.pointer, refund: s.refund, from: s.from,
    edicts: s.edicts, message: s.message.slice(0, s.message.length - (s.message.length && trailingZeros(s.message))),
  }))) });
}
function trailingZeros(b) { let n = 0; for (let i = b.length - 1; i >= 0 && b[i] === 0; i--) n++; return n; }

async function main() {
  const args = process.argv.slice(2);
  if (!existsSync(DECODER)) { console.error(`decoder not found: ${DECODER}`); process.exit(2); }
  const gi = args.indexOf('--golden');
  if (gi < 0) {
    let n = 0;
    for (const [amount, outs] of [[1n, 3], [123456789n, 3], [13179173303n, 2], [(1n << 100n) + 7n, 3]]) {
      const s = burnScript(amount, outs);
      const r = compare(s, outs + 1);
      console.log(`burn ${amount} outs ${outs + 1}: ${r.bad.length ? 'MISMATCH ' + r.bad.join('; ') : 'agree'} · ${bytesToHex(s)}`);
      if (!r.bad.length) n++;
    }
    console.log(`${n}/4 synthetic runestones agree`);
    process.exit(n === 4 ? 0 : 1);
  }
  const txid = args[gi + 1];
  const rpc = makeRpc(RPC_URL, tlsfetchTransport());
  const hex = await rpc('esplora_tx::hex', [txid]);
  const tx = parseTx(hexToBytes(hex));
  const op = tx.outputs.find((o) => isOpReturn(o.script));
  const r = compare(op.script, tx.outputs.length);
  const re = reencode(r.ours, r.stones);
  const same = bytesToHex(re) === bytesToHex(op.script);
  console.log(JSON.stringify({ txid, outputs: tx.outputs.length, agree: !r.bad.length, mismatches: r.bad, reencodeExact: same,
    stones: r.stones.map((s) => ({ pointer: String(s.pointer), refund: String(s.refund), edicts: s.edicts.map((e) => [`${e.id.block}:${e.id.tx}`, String(e.amount), String(e.output)]),
      call: s.message.length ? (({ target, inputs }) => [String(target.block), String(target.tx), ...inputs.slice(0, 4).map(String)])(decodeCellpack(s.message)) : null })) }, null, 1));
  if (args.includes('--save')) {
    const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'fixtures', `${txid}.hex`);
    writeFileSync(out, hex.trim() + '\n');
    console.log(`saved ${out}`);
  }
  process.exit(!r.bad.length && same ? 0 : 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
