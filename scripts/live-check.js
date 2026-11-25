// scripts/live-check.js — READ-ONLY dress rehearsal against mainnet for any FIRE-holding address: runs the page's
// own lib/flow.js steps (identity, decimals, impl pin, per-outpoint scan, fee-coin verification, plan, decode,
// every gate, live simulation) and prints what the page would show. It never signs and never broadcasts: there is
// no wallet here, and the taproot "internal key" written into the throwaway PSBT is a stand-in (the address's own
// output key), so the PSBT could not be signed by anyone even if it were sent somewhere — it is not.
//
//   node scripts/live-check.js <bc1p… address> [amountInFIRE=0.00000001] [feeRate=2]
//
// Transport: tlsfetch-curl (scripts/tlsfetch-transport.js). metashrew_view is throttled to the RPC's limit.
// JOURNAL 2026-11-25 created for fire-burn.

import { makeRpc } from '../lib/chain.js';
import { ordOutputs } from '../lib/chain.js';
import { throttleRpc } from '../lib/throttle.js';
import { tlsfetchTransport } from './tlsfetch-transport.js';
import { RPC_URL, VIEW_CALLS_PER_MINUTE } from '../lib/config.js';
import { readFire, loadCoins, scanFireCoins, verifyFeeCoins, preflight } from '../lib/flow.js';
import { addressToScript } from '../lib/address.js';
import { bytesToHex } from '../lib/bytes.js';
import { parseUnits, formatUnits, FIRE_KEY, ALKANES_OUTPUT_SATS } from '../lib/burn.js';
import { isOpReturn } from '../lib/alkanes.js';
import { existsSync } from 'node:fs';
import { DECODER, compare } from './crosscheck.js';

const [address, amountText = '0.00000001', feeText = '2'] = process.argv.slice(2);
if (!address) { console.error('usage: node scripts/live-check.js <address> [amountFIRE] [feeRate]'); process.exit(2); }
const { script, type } = addressToScript(address);
if (type !== 'p2tr') { console.error('this rehearsal expects a taproot FIRE address'); process.exit(2); }
const standIn = bytesToHex(script.slice(2)); // NOT the holder's internal key; the PSBT is never signed
const acct = { address, publicKey: standIn, type, script };
const accounts = { alkanes: acct, payment: acct };
const short = `${address.slice(0, 8)}…${address.slice(-6)}`;

const rpc = throttleRpc(makeRpc(RPC_URL, tlsfetchTransport()), { perMinute: VIEW_CALLS_PER_MINUTE, onWait: (ms) => console.log(`  (rate limit: waiting ${Math.ceil(ms / 1000)} s)`) });
const log = (k, v) => console.log(`${k.padEnd(22)} ${v}`);

const st = await readFire(rpc);
log('FIRE', `2:77623 name=${st.token.name} symbol=${st.token.symbol}`);
log('read at block', st.height);
log('total supply', `${st.token.totalSupply} (${formatUnits(st.token.totalSupply)} FIRE)`);
log('max supply / decimals', `${st.token.maxSupply} → 8 decimals confirmed`);
log('implementation', `${st.implId} sha256 ${st.implSha}`);
const coins = await loadCoins(rpc, accounts, st.height);
log('holder', `${short} · ${coins.length} coins (${coins.filter((c) => c.indexed).length} confirmed ≤ indexer)`);
const scan = await scanFireCoins(rpc, coins, accounts, st.tag, { onProgress: (k, n) => { if (k === n) log('scanned', `${k}/${n} coins ≤ 1000 sats`); } });
const balance = scan.fireCoins.reduce((s, c) => s + c.alkanes.get(FIRE_KEY), 0n);
log('FIRE coins', `${scan.fireCoins.length} · balance ${balance} (${formatUnits(balance)} FIRE)`);
for (const c of scan.fireCoins) log('  coin', `${c.op.slice(0, 12)}…:${c.vout} ${c.value} sats FIRE ${c.alkanes.get(FIRE_KEY)}${c.alkanes.size > 1 ? ` + ${c.alkanes.size - 1} other alkane(s)` : ''}`);
const ordFire = await ordOutputs(rpc, scan.fireCoins.map((c) => c.op));
const amount = parseUnits(amountText);
const feeRate = Number(feeText);
const fee = await verifyFeeCoins(rpc, coins.filter((c) => !scan.fireCoins.some((f) => f.op === c.op)), accounts, st.tag, st.height, ALKANES_OUTPUT_SATS + 5000n);
log('fee coins', `${fee.clean.length} verified clean, ${fee.rejected.length} skipped`);
for (const r of fee.rejected) log('  skipped', r.why);
const pre = await preflight(rpc, st, {
  amount, feeRate, accounts, fireCoins: scan.fireCoins, feeCoins: fee.clean, ordFire, ordFee: fee.ord,
  alkanesReads: new Map([...scan.reads, ...fee.alkanes]),
});
console.log('\nREVIEW (what the page shows before the wallet prompt):');
console.log(`  ${pre.summary.replace(address, short)}`);
log('unsigned txid', pre.plan.txid);
log('inputs', `${pre.plan.fireCoinsUsed} FIRE coin(s) + ${pre.plan.feeCoinsUsed} fee coin(s)`);
pre.plan.tx.outputs.forEach((o, i) => log(`  out ${i}`, `${o.value} sats ${isOpReturn(o.script) ? 'OP_RETURN ' + bytesToHex(o.script) : '(holder)'}`));
pre.desc.stones.forEach((s, i) => log(`  p${i}`, `pointer ${s.pointer} refund ${s.refund} edicts ${s.edicts.map((e) => `[${e.id.block}:${e.id.tx} ${e.amount} → ${e.output}]`).join(' ') || '—'}${pre.desc.cellpacks[i] ? ` call [${pre.desc.cellpacks[i].target.block}, ${pre.desc.cellpacks[i].target.tx}, ${pre.desc.cellpacks[i].inputs[0]}]` : ''}`));
log('simulate burn N', `ok, returned ${pre.sims.burnN.returned.length} alkanes, fuel ${pre.sims.burnN.gasUsed}`);
log('simulate burn S', `ok=${pre.sims.burnS.ok} (S = ${st.token.totalSupply})`);
log('simulate burn S+1', `ok=${pre.sims.burnS1.ok} error="${pre.sims.burnS1.error}"`);
log('fee', `${pre.desc.fee} sats, est ${pre.plan.estVsize} vB @ ${feeRate}`);
if (existsSync(DECODER)) {
  const op = pre.plan.tx.outputs.find((o) => isOpReturn(o.script));
  const r = compare(op.script, pre.plan.tx.outputs.length);
  log('python decoder', r.bad.length ? `MISMATCH ${r.bad.join('; ')}` : 'agrees (pointer, refunds, edict, cellpack)');
}
console.log('\nALL GATES PASSED (read-only; nothing signed, nothing broadcast)');
