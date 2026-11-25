// lib/flow.js — the burn flow as plain async functions over an injected `rpc` and wallet adapter, so the whole
// path (read → scan → verify → plan → decode → gates → simulate → sign → check → broadcast) runs in node tests
// against an in-memory chain (test/flow.test.js). app.js only renders and wires buttons.
//
// Read path rules (subfrost-app CLAUDE.md SoT-1/SoT-2): alkanes per OUTPOINT via metashrew_view
// protorunesbyoutpoint, contract state via simulate; never address-keyed or espo views. Every read of one
// preflight is pinned to ONE block tag (the indexer height read first), so no figure mixes two states.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { bytesToHex, fromUtf8 } from './bytes.js';
import { addressToScript } from './address.js';
import { serializeTx } from './tx.js';
import { createPsbt, extractSigned } from './psbt.js';
import { idKey } from './route.js';
import {
  indexerHeight, multiSimulate, proxyImplementation, bytecodeSha256, addressUtxos, outpointAlkanes, ordOutputs,
  testMempoolAccept, sendRawTransaction, u128Data,
} from './chain.js';
import { FIRE_ID, FIRE_KEY, OP_BURN, planBurn, describeBurnTx, formatUnits, ALKANES_OUTPUT_SATS } from './burn.js';
import {
  GateError, gateAmount, gateDecimals, gateImpl, gateFeeCoins, gateFireCoins, gatePointers, gateOutputs, gateSimulation,
  gateFee, gateTypedConfirmation, gateSignedTx,
} from './guards.js';
import { inputMetaFor } from './wallets.js';

/** Coins at or below this value are scanned as possible alkane carriers (subfrost-app SoT-1 recipe: dust ≤ 1000). */
export const ALKANE_COIN_MAX_SATS = 1000n;

/** Step 1: FIRE identity, decimals and implementation, all at one tag. */
export async function readFire(rpc, { reviewed } = {}) {
  const height = await indexerHeight(rpc);
  const tag = String(height);
  const r = await multiSimulate(rpc, [99n, 100n, 101n, 102n].map((op) => ({ target: FIRE_ID, inputs: [op] })), tag);
  r.forEach((x, i) => { if (!x.ok) throw new GateError('identity', `FIRE view op ${[99, 100, 101, 102][i]} reverted: ${x.error}`); });
  const token = {
    name: fromUtf8(r[0].data), symbol: fromUtf8(r[1].data),
    totalSupply: u128Data(r[2].data, 'GetTotalSupply'), maxSupply: u128Data(r[3].data, 'GetMaxSupply'),
  };
  if (token.name !== 'FIRE' || token.symbol !== 'FIRE') throw new GateError('identity', `2:77623 answers name "${token.name}" / symbol "${token.symbol}"`);
  gateDecimals(token.maxSupply);
  const impl = await proxyImplementation(rpc, FIRE_ID, tag);
  const implId = `${impl.block}:${impl.tx}`;
  const implSha = await bytecodeSha256(rpc, impl, tag);
  gateImpl({ implId, bytecodeSha256: implSha }, reviewed);
  return { height, tag, token, implId, implSha };
}

/** Step 2: the confirmed coins at each of the wallet's addresses, each tagged with its owner account. */
export async function loadCoins(rpc, accounts, height) {
  const seen = new Set();
  const out = [];
  for (const acct of [accounts.alkanes, accounts.payment]) {
    if (!acct || seen.has(acct.address)) continue;
    seen.add(acct.address);
    const { script } = addressToScript(acct.address);
    for (const u of await addressUtxos(rpc, acct.address)) {
      out.push({ ...u, script, owner: acct, op: `${u.txid}:${u.vout}`, indexed: u.confirmed && u.height > 0 && u.height <= height });
    }
  }
  return out;
}

/** Step 3: read alkanes per outpoint for the alkanes address's small coins (where FIRE lives). */
export async function scanFireCoins(rpc, coins, accounts, tag, { onProgress, shouldStop } = {}) {
  const candidates = coins.filter((c) => c.owner.address === accounts.alkanes.address && c.indexed && c.value <= ALKANE_COIN_MAX_SATS);
  const reads = new Map();
  let k = 0;
  for (const c of candidates) {
    if (shouldStop && shouldStop()) break;
    reads.set(c.op, await outpointAlkanes(rpc, c.txid, c.vout, tag));
    k++;
    if (onProgress) onProgress(k, candidates.length);
  }
  const fireCoins = [];
  for (const c of candidates) {
    const a = reads.get(c.op);
    if (!a || a.empty) continue;
    const alkanes = new Map();
    for (const e of a.entries) alkanes.set(idKey(e.id), (alkanes.get(idKey(e.id)) || 0n) + e.amount);
    if ((alkanes.get(FIRE_KEY) || 0n) > 0n) fireCoins.push({ ...c, alkanes });
  }
  return { reads, fireCoins, scanned: k, total: candidates.length };
}

/**
 * Step 4: verify fee candidates (largest first) until the CLEAN ones cover `needSats`: alkanes by outpoint, then
 * ord in one batch per round. A rejected coin never counts toward the target (a dirty largest coin used to end the
 * search early with too little clean BTC). ord unreachable ⇒ refuse to pick any fee coin.
 */
export async function verifyFeeCoins(rpc, coins, accounts, tag, height, needSats) {
  const pool = coins.filter((c) => c.indexed && c.value > ALKANE_COIN_MAX_SATS)
    .sort((a, b) => (a.value === b.value ? 0 : a.value > b.value ? -1 : 1));
  const clean = [], rejected = [], alkanes = new Map(), ord = new Map();
  let sum = 0n, next = 0;
  while (sum < needSats && next < pool.length) {
    const round = [];
    let roundSum = 0n;
    while (sum + roundSum < needSats && next < pool.length) {
      const c = pool[next++];
      const a = await outpointAlkanes(rpc, c.txid, c.vout, tag);
      alkanes.set(c.op, a);
      // early skip only saves an ord lookup; gateFeeCoins below is the check (a mutation removing this stays green)
      if (a.entries.length) { rejected.push({ op: c.op, why: `[fee-coin] ${c.op} carries alkanes — never spent as fee` }); continue; }
      round.push(c);
      roundSum += c.value;
    }
    if (!round.length) break;
    let rows;
    try { rows = await ordOutputs(rpc, round.map((c) => c.op)); } catch (e) {
      throw new GateError('fee-coin', `ord is unreachable (${e.message}) — this page will not pick fee coins it cannot check for inscriptions`);
    }
    for (const [k, v] of rows) ord.set(k, v);
    for (const c of round) {
      try { gateFeeCoins([c], { alkanes, ord, indexerHeight: height }); clean.push(c); sum += c.value; } catch (e) { rejected.push({ op: c.op, why: e.message }); }
    }
  }
  return { clean, rejected, alkanes, ord };
}

/** Step 5: plan + decode + every pre-wallet gate + live simulation. Nothing here touches the wallet. */
export async function preflight(rpc, state, { amount, feeRate, accounts, fireCoins, feeCoins, ordFire, alkanesReads, ordFee }) {
  const balance = fireCoins.reduce((s, c) => s + (c.alkanes.get(FIRE_KEY) || 0n), 0n);
  gateAmount(amount, balance);
  const holderScript = addressToScript(accounts.alkanes.address).script;
  const changeScript = addressToScript(accounts.payment.address).script;
  const withMeta = (c) => ({ ...c, meta: inputMetaFor(c, c.owner) });
  const plan = planBurn({ amount, fireCoins: fireCoins.map(withMeta), feeCoins: feeCoins.map(withMeta), holderScript, changeScript, feeRate });
  const usedFire = plan.coins.slice(0, plan.fireCoinsUsed);
  const usedFee = plan.coins.slice(plan.fireCoinsUsed);
  gateFireCoins(usedFire, { alkanes: alkanesReads, ord: ordFire, indexerHeight: state.height });
  gateFeeCoins(usedFee, { alkanes: alkanesReads, ord: ordFee, indexerHeight: state.height });
  const inputSheets = plan.coins.map((c) => (c.alkanes ? new Map(c.alkanes) : new Map()));
  const prevouts = plan.coins.map((c) => ({ value: c.value, script: c.script }));
  const desc = describeBurnTx(plan.tx, inputSheets, prevouts);
  gatePointers(desc, plan.tx, { holderScript, amount, inputSheets });
  gateOutputs(plan.tx, { holderScript, changeScript });
  gateFee(plan, desc);
  const S = state.token.totalSupply;
  // simulate the EXACT call the bytes carry: p1's decoded cellpack, incl. the zero inputs the 15-byte packing adds
  const exact = desc.cellpacks[1];
  const fire = (v) => ({ target: exact.target, inputs: exact.inputs, alkanes: [{ id: FIRE_ID, value: v }] });
  const [burnN, burnS, burnS1] = await multiSimulate(rpc, [fire(amount), fire(S), fire(S + 1n)], state.tag);
  gateSimulation({ amount, supply: S, burnN, burnS, burnS1 });
  const psbt = createPsbt(plan.tx, plan.coins.map((c) => c.meta));
  const holderGets = desc.route.outputs.get(Number(desc.runestone.pointer)) || new Map();
  const otherAlkanes = [...holderGets].filter(([k]) => k !== FIRE_KEY);
  const summary = `burns ${formatUnits(desc.burned)} FIRE · returns ${formatUnits(holderGets.get(FIRE_KEY) || 0n)} FIRE`
    + `${otherAlkanes.length ? ` + ${otherAlkanes.length} other alkane${otherAlkanes.length > 1 ? 's' : ''}` : ''}`
    + ` to ${accounts.alkanes.address} · fee ${desc.fee} sats`;
  return { plan, desc, sims: { burnN, burnS, burnS1 }, psbt, summary, holderGets, holderScript, changeScript };
}

/** Step 6: typed confirmation → wallet → the signed tx must be the built tx. */
/**
 * Re-read 2:77623's implementation at the indexer's CURRENT tip: it must still be the one checked at connect (alkane
 * bytecode at an id is immutable, so the id is enough). Run before the wallet prompt and before broadcast, so a page
 * left open across a FIRE upgrade cannot sign or send against unreviewed code (review finding 3).
 */
export async function recheckImpl(rpc, state) {
  const impl = await proxyImplementation(rpc, FIRE_ID, 'latest');
  const now = `${impl.block}:${impl.tx}`;
  if (now !== state.implId) throw new GateError('impl', `2:77623 now runs ${now} (was ${state.implId} when checked) — reconnect to re-check`);
}

export async function signAndCheck(rpc, wallet, provider, pre, typed, state) {
  gateTypedConfirmation(typed, pre.plan.amount);
  await recheckImpl(rpc, state);
  const totalIn = pre.plan.coins.reduce((s, c) => s + c.value, 0n);
  const totalOut = pre.plan.tx.outputs.reduce((s, o) => s + o.value, 0n);
  const answer = await wallet.sign(provider, pre.psbt, {
    inputOwners: pre.plan.coins.map((c) => c.owner.address), totalIn, totalOut,
    nIn: pre.plan.tx.inputs.length, nOut: pre.plan.tx.outputs.length,
  });
  const signed = extractSigned(answer);
  gateSignedTx(signed, pre.plan);
  return { signed, hex: bytesToHex(serializeTx(signed)) };
}

/** Step 7: node policy dry run (no broadcast). */
export async function mempoolCheck(rpc, hex, plan) {
  const v = await testMempoolAccept(rpc, hex);
  if (!v.allowed) throw new GateError('mempool', `the node would reject it: ${v.reason || 'no reason given'}`);
  if (v.txid && v.txid !== plan.txid) throw new GateError('mempool', `node computed txid ${v.txid}, built ${plan.txid}`);
  return v;
}

/** Step 8: broadcast (only after an explicit second click in the page). */
export async function broadcast(rpc, hex, plan, state) {
  await recheckImpl(rpc, state);
  const id = await sendRawTransaction(rpc, hex);
  if (id !== plan.txid) throw new GateError('broadcast', `node answered txid ${id}, built ${plan.txid}`);
  return id;
}

export { ALKANES_OUTPUT_SATS };
