// app.js — DOM wiring for FIRE burn. All logic lives in lib/flow.js (tested in node); this file renders state and
// calls the steps in order. Rules: textContent only (the CSP enforces Trusted Types, so an innerHTML sink would
// throw); nothing is written to localStorage/sessionStorage/IndexedDB; every error stops the flow and is shown;
// a new wallet connection, a changed amount or a changed fee rate discards the reviewed transaction.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { rpcUrlFor, VIEW_CALLS_PER_MINUTE, EXPLORER_TX } from './lib/config.js';
import { makeRpc, fetchTransport, indexerHeight, ordOutputs, CorsOrNetworkError } from './lib/chain.js';
import { throttleRpc } from './lib/throttle.js';
import { detectWallets } from './lib/wallets.js';
import { readFire, loadCoins, scanFireCoins, verifyFeeCoins, preflight, signAndCheck, mempoolCheck, broadcast, ALKANE_COIN_MAX_SATS } from './lib/flow.js';
import { FIRE_KEY, FIRE_DECIMALS, formatUnits, parseUnits, ALKANES_OUTPUT_SATS } from './lib/burn.js';
import { MAX_FEE_RATE } from './lib/guards.js';
import { estimateVsize } from './lib/tx.js';
import { scriptToAddress } from './lib/address.js';
import { bytesToHex } from './lib/bytes.js';

if (window.top !== window.self) {
  document.body.textContent = 'FIRE burn refuses to run inside a frame.';
  throw new Error('framed');
}

const $ = (id) => document.getElementById(id);
const show = (id, on = true) => { $(id).hidden = !on; };
const set = (id, text) => { $(id).textContent = text; };

let waitNote = '';
const rpc = throttleRpc(makeRpc(rpcUrlFor(globalThis.location ? globalThis.location.origin : ''), fetchTransport(window.fetch.bind(window))), {
  perMinute: VIEW_CALLS_PER_MINUTE,
  onWait: (ms) => { waitNote = `waiting ${Math.ceil(ms / 1000)} s for the RPC rate limit…`; set('scan-status', waitNote); },
});

const S = { wallet: null, provider: null, accounts: null, chain: null, coins: [], scan: null, ordFire: new Map(), pre: null, signed: null, stop: false };
// Generations (review finding 9): a connect or a build that finishes after the user moved on must not write state.
let walletGen = 0, buildGen = 0;

function error(e) {
  const msg = e instanceof CorsOrNetworkError ? e.message : (e && e.message) || String(e);
  set('error', msg);
  show('error');
}
function clearError() { show('error', false); set('error', ''); }

function discardReview() {
  buildGen++;
  S.pre = null; S.signed = null;
  show('s-review', false); show('s-send', false);
  $('sign').disabled = true; set('confirm', ''); $('confirm').value = '';
}

async function rpcStatus() {
  try {
    const h = await indexerHeight(rpc);
    set('rpc-status', `RPC reachable · alkanes indexer at block ${h}`);
    $('rpc-status').className = 'status ok';
  } catch (e) {
    $('rpc-status').className = 'status bad';
    set('rpc-status', e instanceof CorsOrNetworkError
      ? 'This page cannot read the RPC from this origin (the RPC does not allow it: CORS). Nothing can be checked, so nothing can be burned here.'
      : `RPC check failed: ${e.message}`);
  }
}

function renderWallets() {
  const found = detectWallets(window);
  const box = $('wallet-buttons');
  box.textContent = '';
  show('wallet-none', found.length === 0);
  for (const w of found) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = `Connect ${w.name}`;
    b.addEventListener('click', () => connect(w));
    box.appendChild(b);
  }
}

async function connect(w) {
  clearError(); discardReview();
  const my = ++walletGen;
  S.stop = true; // stop a scan still running for the previous wallet
  S.wallet = null; S.accounts = null; S.chain = null; S.scan = null;
  show('s-token', false); show('s-coins', false); show('s-amount', false);
  try {
    const provider = w.provider(window);
    const accounts = await w.connect(provider);
    if (my !== walletGen) return;
    S.wallet = w; S.provider = provider; S.accounts = accounts;
    set('w-name', w.name); set('w-alk', accounts.alkanes.address); set('w-pay', accounts.payment.address);
    show('wallet-info');
    const chain = await readFire(rpc);
    if (my !== walletGen) return;
    S.chain = chain;
    set('t-id', `2:77623 · ${S.chain.token.name} / ${S.chain.token.symbol}`);
    set('t-height', String(S.chain.height));
    set('t-supply', `${formatUnits(S.chain.token.totalSupply)} FIRE`);
    set('t-dec', `${FIRE_DECIMALS} (max supply ${formatUnits(S.chain.token.maxSupply)} = 2,100,000)`);
    set('t-impl', `${S.chain.implId} · sha256 ${S.chain.implSha.slice(0, 16)}… (reviewed)`);
    show('s-token');
    const coins = await loadCoins(rpc, accounts, S.chain.height);
    if (my !== walletGen) return;
    S.coins = coins;
    await scan(my);
  } catch (e) { error(e); }
}

async function scan(my) {
  show('s-coins');
  S.stop = false;
  show('scan-stop');
  set('scan-status', 'Reading the alkanes on each small coin at your FIRE address…');
  const height = S.chain.height;
  const result = await scanFireCoins(rpc, S.coins, S.accounts, S.chain.tag, {
    onProgress: (k, n) => { if (my === walletGen) set('scan-status', `Read ${k} of ${n} coins (≤ ${ALKANE_COIN_MAX_SATS} sats) at block ${height}.`); },
    shouldStop: () => S.stop || my !== walletGen,
  });
  const ordFire = await ordOutputs(rpc, result.fireCoins.map((c) => c.op));
  if (my !== walletGen) return;
  show('scan-stop', false);
  S.scan = result; S.ordFire = ordFire;
  const bal = S.scan.fireCoins.reduce((s, c) => s + c.alkanes.get(FIRE_KEY), 0n);
  set('fire-balance', formatUnits(bal));
  set('fire-coins', `(${S.scan.fireCoins.length} coin${S.scan.fireCoins.length === 1 ? '' : 's'}; scanned ${S.scan.scanned} of ${S.scan.total})`);
  show('s-amount', bal > 0n);
}

function amountBase() {
  try { return parseUnits($('amount').value, FIRE_DECIMALS); } catch { return null; }
}

function onAmountInput() {
  discardReview();
  const a = amountBase();
  set('amount-base', a === null ? '—' : a.toString());
}

async function check() {
  clearError(); discardReview();
  const my = buildGen, inputs = `${$('amount').value}|${$('feerate').value}`;
  try {
    if (!S.scan) throw new Error('connect a wallet and let the scan finish first');
    const amount = parseUnits($('amount').value, FIRE_DECIMALS);
    const feeRate = Number($('feerate').value);
    if (!(feeRate >= 1 && feeRate <= MAX_FEE_RATE)) throw new Error(`fee rate must be between 1 and ${MAX_FEE_RATE} sat/vB`);
    const fireCoins = S.scan.fireCoins;
    // upper-bound size: every FIRE coin plus two fee coins at the largest input size we support
    const est = estimateVsize([...fireCoins.map(() => 'p2sh'), 'p2sh', 'p2sh'], [new Uint8Array(34), new Uint8Array(34), new Uint8Array(80)]);
    const need = ALKANES_OUTPUT_SATS + BigInt(Math.ceil(est * feeRate)) + 1000n;
    set('scan-status', 'Checking fee coins for alkanes, inscriptions and runes…');
    const fee = await verifyFeeCoins(rpc, S.coins.filter((c) => !S.scan.fireCoins.some((f) => f.op === c.op)), S.accounts, S.chain.tag, S.chain.height, need);
    const alkanesReads = new Map([...S.scan.reads, ...fee.alkanes]);
    const pre = await preflight(rpc, S.chain, {
      amount, feeRate, accounts: S.accounts, fireCoins, feeCoins: fee.clean,
      ordFire: S.ordFire, ordFee: fee.ord, alkanesReads,
    });
    // the amount or fee changed (or another wallet connected) while this was checking: show nothing stale
    if (my !== buildGen || inputs !== `${$('amount').value}|${$('feerate').value}`) return;
    S.pre = pre;
    renderReview(fee.rejected);
  } catch (e) { error(e); }
}

function li(text, ok = true) {
  const el = document.createElement('li');
  el.className = ok ? 'ok' : 'bad';
  el.textContent = text;
  return el;
}

function renderReview(rejected) {
  const p = S.pre;
  set('summary', p.summary);
  const g = $('gates');
  g.textContent = '';
  g.appendChild(li(`FIRE 2:77623 answers FIRE/FIRE; decimals ${FIRE_DECIMALS} confirmed by its max supply; implementation ${S.chain.implId} is a reviewed build`));
  g.appendChild(li(`Every pointer and refund points at your FIRE address (output 0); nothing goes to the OP_RETURN or anyone else`));
  g.appendChild(li(`Fee coins carry no alkanes, inscriptions or runes (checked per coin)`));
  g.appendChild(li(`Live simulation at block ${S.chain.height}: burning ${formatUnits(p.plan.amount)} succeeds and returns nothing; supply moves by exactly the amount sent`));
  g.appendChild(li(`Fee ${p.desc.fee} sats ≈ ${(Number(p.desc.fee) / p.plan.estVsize).toFixed(2)} sat/vB (estimated ${p.plan.estVsize} vB)`));
  for (const r of rejected) g.appendChild(li(`skipped fee coin ${r.op}: ${r.why}`, false));
  const lines = [];
  lines.push(`txid (unsigned): ${p.plan.txid}`);
  p.plan.coins.forEach((c, i) => lines.push(`in  ${i}: ${c.op}  ${c.value} sats${c.alkanes ? `  FIRE ${formatUnits(c.alkanes.get(FIRE_KEY) || 0n)}` : '  (fee)'}`));
  p.plan.tx.outputs.forEach((o, i) => lines.push(`out ${i}: ${o.value} sats  ${scriptToAddress(o.script) || 'OP_RETURN ' + bytesToHex(o.script)}`));
  p.desc.stones.forEach((s, i) => lines.push(`p${i}: pointer ${s.pointer} refund ${s.refund} edicts ${JSON.stringify(s.edicts.map((e) => [`${e.id.block}:${e.id.tx}`, e.amount.toString(), Number(e.output)]))}${p.desc.cellpacks[i] ? ` call [${p.desc.cellpacks[i].target.block}, ${p.desc.cellpacks[i].target.tx}, ${p.desc.cellpacks[i].inputs[0]}]` : ''}`));
  lines.push(`fuel used in simulation: ${p.sims.burnN.gasUsed}`);
  set('decoded', lines.join('\n'));
  set('confirm-want', formatUnits(p.plan.amount));
  show('s-review');
}

async function sign() {
  clearError();
  try {
    const typed = $('confirm').value;
    $('sign').disabled = true;
    set('send-status', `Waiting for ${S.wallet.name}…`);
    show('s-send');
    const r = await signAndCheck(rpc, S.wallet, S.provider, S.pre, typed, S.chain);
    S.signed = r;
    set('send-status', 'Signed transaction is the one reviewed (same txid). Asking the node whether it would accept it…');
    await mempoolCheck(rpc, r.hex, S.pre.plan);
    set('send-status', `The node would accept it. Nothing has been sent yet. Burning ${formatUnits(S.pre.plan.amount)} FIRE is final.`);
    show('broadcast');
  } catch (e) { error(e); $('sign').disabled = false; }
}

async function doBroadcast() {
  clearError();
  try {
    $('broadcast').disabled = true;
    const id = await broadcast(rpc, S.signed.hex, S.pre.plan, S.chain);
    set('send-status', 'Broadcast. It counts once it confirms.');
    const a = document.createElement('a');
    a.href = EXPLORER_TX + id; a.rel = 'noopener noreferrer'; a.target = '_blank'; a.textContent = id;
    $('txid').textContent = '';
    $('txid').appendChild(a);
    show('broadcast', false);
    // the spent coins are gone: no second build from this scan (review finding 10) — reconnect to burn again
    S.scan = null;
    show('s-amount', false);
    set('fire-coins', '(spent by the burn above — reconnect your wallet to burn again)');
  } catch (e) { error(e); $('broadcast').disabled = false; }
}

$('amount').addEventListener('input', onAmountInput);
$('feerate').addEventListener('input', discardReview);
$('amount-max').addEventListener('click', () => {
  if (!S.scan) return;
  $('amount').value = formatUnits(S.scan.fireCoins.reduce((s, c) => s + c.alkanes.get(FIRE_KEY), 0n));
  onAmountInput();
});
$('check').addEventListener('click', check);
$('confirm').addEventListener('input', () => { $('sign').disabled = !S.pre || $('confirm').value.trim() !== formatUnits(S.pre.plan.amount); });
$('sign').addEventListener('click', sign);
$('broadcast').addEventListener('click', doBroadcast);
$('scan-stop').addEventListener('click', () => { S.stop = true; });

rpcStatus();
setTimeout(renderWallets, 400); // wallets inject asynchronously
