// scripts/canary-verify.js — READ-ONLY proof of a confirmed burn, for the operator's canary (and any later burn).
//
//   node scripts/canary-verify.js <txid> <amountInFIRE>
//
// Checks, all from the chain:
//   1. the tx decodes to exactly this page's shape (gatePointers on the bytes, with each input's alkanes read at the
//      block BEFORE the tx confirmed: metashrew_view honours a block tag);
//   2. the alkanes trace of p1 (shadow vout = outputs + 2): enter 2:77623 with inputs [88, …] and incoming exactly
//      [2:77623 × N], exit SUCCESS, nothing returned;
//   3. output 0 now holds exactly (input FIRE − N) plus every other input alkane (protorunesbyoutpoint at the tx's
//      block), and the change output holds none;
//   4. FIRE GetTotalSupply at h−1 vs h: reported, and must have dropped by at least N (other mints/burns in the same
//      block can move it too — the trace in step 2 is the exact proof).
// The canary checklist (README "Operator canary") calls this after the operator broadcasts.
//
// Trace schema: alkanes-rs crates/alkanes-support/proto/alkanes.proto:45-104 (AlkanesTrace → events oneof
// enter_context(1){call_type, TraceContext{Context{myself, caller, inputs, vout, incoming_alkanes}, fuel}} /
// exit_context(2){status: 0 SUCCESS | 1 FAILURE, response: ExtendedCallResponse}); view: src/view.rs:439.
// JOURNAL 2026-11-25 created for fire-burn.

import { makeRpc, outpointAlkanes, multiSimulate, u128Data } from '../lib/chain.js';
import { throttleRpc } from '../lib/throttle.js';
import { tlsfetchTransport } from './tlsfetch-transport.js';
import { RPC_URL, VIEW_CALLS_PER_MINUTE } from '../lib/config.js';
import { parseTx } from '../lib/tx.js';
import { hexToBytes, bytesToHex, concat, reversed } from '../lib/bytes.js';
import { pbFields, pbVarint, decUint128 } from '../lib/protobuf.js';
import { describeBurnTx, parseUnits, formatUnits, FIRE_ID, FIRE_KEY } from '../lib/burn.js';
import { gatePointers } from '../lib/guards.js';
import { idKey } from '../lib/route.js';
import { fileURLToPath } from 'node:url';

const lf = (f, b) => concat(pbVarint((f << 3) | 2), pbVarint(b.length), b);

function decId(b) { const f = pbFields(b); const g = (n) => { const x = f.find((y) => y.field === n); return x ? decUint128(x.value) : 0n; }; return { block: g(1), tx: g(2) }; }
function decTransfer(b) { const f = pbFields(b); const id = f.find((y) => y.field === 1); const v = f.find((y) => y.field === 2); return { id: id ? decId(id.value) : { block: 0n, tx: 0n }, value: v ? decUint128(v.value) : 0n }; }

/** Raw AlkanesTrace bytes → [{ kind: 'enter', myself, inputs, incoming } | { kind: 'exit', ok, returned }]. */
export function decodeTrace(buf) {
  return pbFields(buf).filter((e) => e.field === 1).map((e) => {
    const ev = pbFields(e.value)[0];
    if (!ev) return { kind: 'empty' };
    if (ev.field === 1) {
      const tc = pbFields(ev.value).find((x) => x.field === 2);
      const ctx = tc ? pbFields(tc.value).find((x) => x.field === 1) : null;
      const cf = ctx ? pbFields(ctx.value) : [];
      const my = cf.find((x) => x.field === 1);
      return {
        kind: 'enter',
        myself: my ? decId(my.value) : null,
        inputs: cf.filter((x) => x.field === 3).map((x) => decUint128(x.value)),
        incoming: cf.filter((x) => x.field === 5).map((x) => decTransfer(x.value)),
      };
    }
    if (ev.field === 2) {
      const xf = pbFields(ev.value);
      const status = xf.find((x) => x.field === 1);
      const resp = xf.find((x) => x.field === 2);
      return { kind: 'exit', ok: !status || status.value === 0n, returned: resp ? pbFields(resp.value).filter((x) => x.field === 1).map((x) => decTransfer(x.value)) : [] };
    }
    return { kind: 'create' };
  });
}

export async function readTrace(rpc, txid, vout, blockTag = 'latest') {
  const req = concat(lf(1, reversed(hexToBytes(txid))), pbVarint(2 << 3), pbVarint(vout));
  const hex = await rpc('metashrew_view', ['trace', '0x' + bytesToHex(req), blockTag]);
  return decodeTrace(hexToBytes(hex));
}

async function main() {
  const [txid, amountText] = process.argv.slice(2);
  if (!txid || !amountText) { console.error('usage: node scripts/canary-verify.js <txid> <amountFIRE>'); process.exit(2); }
  const amount = parseUnits(amountText);
  const rpc = throttleRpc(makeRpc(RPC_URL, tlsfetchTransport()), { perMinute: VIEW_CALLS_PER_MINUTE, onWait: (ms) => console.log(`  (rate limit: waiting ${Math.ceil(ms / 1000)} s)`) });
  const status = await rpc('esplora_tx', [txid]);
  if (!status.status || !status.status.confirmed) { console.log('not confirmed yet'); process.exit(3); }
  const h = status.status.block_height;
  const tx = parseTx(hexToBytes(await rpc('esplora_tx::hex', [txid])));
  const prevTag = String(h - 1), tag = String(h);
  const inputSheets = [], prevouts = [];
  for (const i of tx.inputs) {
    const a = await outpointAlkanes(rpc, i.txid, i.vout, prevTag);
    const m = new Map();
    for (const e of a.entries) m.set(idKey(e.id), (m.get(idKey(e.id)) || 0n) + e.amount);
    inputSheets.push(m);
    const prev = await rpc('esplora_tx', [i.txid]);
    const o = prev.vout[i.vout];
    prevouts.push({ value: BigInt(o.value), script: hexToBytes(o.scriptpubkey) });
  }
  const desc = describeBurnTx(tx, inputSheets, prevouts);
  gatePointers(desc, tx, { holderScript: tx.outputs[0].script, amount, inputSheets });
  console.log(`1. shape OK at block ${h}: burns ${formatUnits(desc.burned)} FIRE, fee ${desc.fee} sats`);
  const p1 = tx.outputs.length + 2;
  const tr = await readTrace(rpc, txid, p1, tag);
  const enter = tr.find((e) => e.kind === 'enter');
  const exit = tr.filter((e) => e.kind === 'exit').at(-1);
  const inFire = enter ? enter.incoming.filter((t) => idKey(t.id) === FIRE_KEY).reduce((s, t) => s + t.value, 0n) : -1n;
  const traceOk = enter && enter.myself && idKey(enter.myself) === FIRE_KEY && enter.inputs[0] === 88n
    && enter.incoming.filter((t) => t.value > 0n).length === 1 && inFire === amount && exit && exit.ok
    && exit.returned.filter((t) => t.value > 0n).length === 0;
  console.log(`2. trace ${txid.slice(0, 12)}…:${p1}: enter ${enter && enter.myself ? idKey(enter.myself) : '?'} op ${enter ? enter.inputs[0] : '?'} incoming FIRE ${inFire} · exit ${exit ? (exit.ok ? 'SUCCESS' : 'FAILURE') : '?'} returned ${exit ? exit.returned.filter((t) => t.value > 0n).length : '?'} → ${traceOk ? 'OK' : 'MISMATCH'}`);
  const out0 = await outpointAlkanes(rpc, txid, 0, tag);
  const got = new Map(out0.entries.map((e) => [idKey(e.id), e.amount]));
  const want = desc.route.outputs.get(0) || new Map();
  const same = got.size === want.size && [...want].every(([k, v]) => got.get(k) === v);
  console.log(`3. output 0 holds ${[...got].map(([k, v]) => `${k}=${v}`).join(', ') || 'nothing'} → ${same ? 'as expected' : 'MISMATCH, expected ' + [...want].map(([k, v]) => `${k}=${v}`).join(', ')}`);
  let changeClean = true;
  for (let v = 1; v < tx.outputs.length - 1; v++) { const a = await outpointAlkanes(rpc, txid, v, tag); if (a.entries.length) changeClean = false; }
  console.log(`   change output(s) carry alkanes: ${changeClean ? 'no' : 'YES — MISMATCH'}`);
  const [s0] = await multiSimulate(rpc, [{ target: FIRE_ID, inputs: [101n] }], prevTag);
  const [s1] = await multiSimulate(rpc, [{ target: FIRE_ID, inputs: [101n] }], tag);
  const d = u128Data(s0.data, 'supply h-1') - u128Data(s1.data, 'supply h');
  console.log(`4. GetTotalSupply ${prevTag} → ${tag}: Δ = −${d} (burn ${amount}; other activity in the block can add to it)`);
  const ok = traceOk && same && changeClean && d >= amount;
  console.log(ok ? 'CANARY VERIFIED' : 'CANARY CHECK FAILED');
  process.exit(ok ? 0 : 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
