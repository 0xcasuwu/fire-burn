// lib/route.js — a model of how the alkanes indexer routes protorunes through a transaction's protostones.
//
// WHY: gate 4 must say "burns X FIRE · returns Y FIRE + other alkanes to <addr>" from the BYTES we are about to sign,
// not from the builder's intent. This re-derives it: decode the OP_RETURN, decipher the protostones, then replay
// the indexer's routing over the alkanes each input carries (read per outpoint).
//
// MIRRORS alkanes-rs @ 52850a22 crates/protorune/src/lib.rs:940-1100 `index_protostones` (alkanes protocol tag 1):
//   - every input alkane goes to the FIRST protostone whose protocol tag matches (lib.rs:1010-1020), i.e. its
//     shadow vout = numOutputs + 1 + position (lib.rs:1023);
//   - protostone with a message (lib.rs:1036-1056): the message runs on its shadow vout's sheet
//     (protostone.rs:127-131); on success the call's returned alkanes go to `pointer` (reconcile), then the
//     pointer's sheet is taken, the stone's edicts run on it and the leftover goes back to the pointer; on a revert
//     the shadow sheet goes to `refund` (protostone.rs:190-201) and the stone's edicts do NOT run;
//   - protostone without a message (lib.rs:1057-1061): its shadow sheet is taken, edicts run, leftover → pointer
//     (default_output when absent, lib.rs:56-63);
//   - edict amount 0 = everything, otherwise min(amount, balance) (lib.rs:320-346); edict output == numOutputs is
//     the "spread to every non-OP_RETURN output" special case (lib.rs:98-131) — modelled as a refusal here, the page
//     never builds it.
// Balances left on an OP_RETURN output or on a shadow vout after the last stone are LOST (save_balances only
// keeps them as records nobody can spend); `lost` reports them so a guard can refuse.
//
// The contract call is a parameter (`callOutcome(sheet) → { ok, returned: Map }`), so the burn's effect is stated
// once (lib/burn.js `fireBurnOutcome`, from the reviewed source) and tested separately.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { isOpReturn } from './alkanes.js';

export const idKey = (id) => `${BigInt(id.block)}:${BigInt(id.tx)}`;

function add(sheets, vout, key, amount) {
  if (amount === 0n) return;
  if (!sheets.has(vout)) sheets.set(vout, new Map());
  const m = sheets.get(vout);
  m.set(key, (m.get(key) || 0n) + amount);
}

function pipe(sheets, from, to) {
  for (const [k, v] of from) add(sheets, to, k, v);
}

/**
 * @param {object} p
 * @param {Map<string,bigint>[]} p.inputSheets  alkanes per input (idKey → amount)
 * @param {Uint8Array[]} p.outputScripts         the tx's output scripts (to know which are OP_RETURN)
 * @param {object[]} p.protostones               decipherProtostones() result
 * @param {(sheet: Map<string,bigint>, stone: object) => {ok: boolean, returned: Map<string,bigint>, consumed?: Map<string,bigint>}} p.callOutcome
 * @returns {{ outputs: Map<number, Map<string,bigint>>, lost: Map<number, Map<string,bigint>>, calls: object[] }}
 */
export function routeProtostones({ inputSheets, outputScripts, protostones, callOutcome }) {
  const n = outputScripts.length;
  const defaultOutput = (() => { for (let i = 0; i < n; i++) if (!isOpReturn(outputScripts[i])) return i; return 0; })();
  const sheets = new Map();
  const calls = [];
  const first = protostones.findIndex((s) => s.protocolTag === 1n);
  if (first >= 0) for (const s of inputSheets) pipe(sheets, s, n + 1 + first);
  else return { outputs: new Map(), lost: new Map(), calls, noProtostone: true };

  const take = (vout) => { const m = sheets.get(vout) || new Map(); sheets.delete(vout); return m; };

  protostones.forEach((stone, i) => {
    const shadow = n + 1 + i;
    const pointer = stone.pointer !== undefined ? Number(stone.pointer) : defaultOutput;
    if (stone.pointer !== undefined && (stone.pointer > BigInt(n + protostones.length))) throw new Error(`protostone ${i}: pointer out of range`);
    if (stone.refund !== undefined && (stone.refund > BigInt(n + protostones.length))) throw new Error(`protostone ${i}: refund out of range`);
    let prior = new Map();
    let failed = false;
    if (stone.message.length && stone.protocolTag === 1n) {
      if (stone.pointer === undefined || stone.refund === undefined) throw new Error(`protostone ${i}: message without pointer/refund (the indexer errors)`);
      const incoming = new Map(sheets.get(shadow) || new Map());
      const outcome = callOutcome(incoming, stone);
      calls.push({ stone: i, incoming, ...outcome });
      if (outcome.ok) {
        take(shadow);
        pipe(sheets, outcome.returned, pointer);
        prior = take(pointer);
      } else {
        failed = true;
        pipe(sheets, take(shadow), Number(stone.refund));
      }
    } else {
      prior = take(shadow);
    }
    if (!failed) {
      for (const e of stone.edicts) {
        if (e.id.block === 0n && e.id.tx !== 0n) throw new Error('invalid edict id');
        if (e.output === BigInt(n)) throw new Error(`protostone ${i}: edict to output ${n} spreads over every output — refused`);
        const k = idKey(e.id);
        const bal = prior.get(k) || 0n;
        const amt = e.amount === 0n ? bal : (e.amount < bal ? e.amount : bal);
        if (amt > 0n) { prior.set(k, bal - amt); add(sheets, Number(e.output), k, amt); }
      }
      for (const [k, v] of prior) if (v > 0n) add(sheets, pointer, k, v);
    }
  });

  const outputs = new Map(), lost = new Map();
  for (const [vout, m] of sheets) {
    const clean = new Map([...m].filter(([, v]) => v > 0n));
    if (!clean.size) continue;
    if (vout < n && !isOpReturn(outputScripts[vout])) outputs.set(vout, clean);
    else lost.set(vout, clean);
  }
  return { outputs, lost, calls };
}
