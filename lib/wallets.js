// lib/wallets.js — injected browser-wallet adapters (no SDK packages). Each adapter: detect(), connect(), sign().
//
// CALL SHAPES are copied from code that runs in production in subfrost-app (@ 8d9553d1c),
// not from memory or web docs:
//   UniSat   connect: unisat.requestAccounts() + getPublicKey()        lib/walletCore/sdkRemoved/browserWallets.ts:596-605
//            sign:    unisat.signPsbt(hex, {autoFinalized:true, toSignInputs:[{index,address}]}) → hex
//                                                                      lib/wallet/browserWalletSigning.ts:572-578
//   OYL      connect: oyl.getAddresses() → {taproot, nativeSegwit}      browserWallets.ts:704-714
//            sign:    oyl.signPsbt({psbt:hex, finalize:false, broadcast:false}) → {psbt:hex}
//                                                                      browserWalletSigning.ts:731,750
//   Xverse   connect: XverseProviders.BitcoinProvider.request('getAccounts',{purposes:['ordinals','payment']})
//                                                                      context/WalletContext.tsx:1500-1516
//            sign:    request('signPsbt',{psbt:base64, signInputs:{addr:[i]}, broadcast:false}) → result.psbt (base64)
//                                                                      browserWalletSigning.ts:394-438
//   Leather  connect: LeatherProvider.request('getAddresses') → result.addresses[{symbol,type,address,publicKey}]
//                                                                      WalletContext.tsx:1518-1534
//            sign:    request('signPsbt',{hex, signAtIndex:[i], broadcast:false}) → result.hex
//                                                                      browserWallets.ts:472-479 (the app's adapter;
//                                                                      the app has no direct Leather signer)
//   SUBFROST window.subfrost (frozen object, connect-gate approval per site)  constants/wallets.ts:29-42,118-128
//            connect: requestAccounts() → string[], getPublicKey() → hex   WalletContext.tsx:2192-2210
//            sign:    subfrost.signPsbt(hex, {feeRate}) → hex, self-finalized; WITHOUT a declared feeRate the
//                     extension's fee patch rewrites a PSBT built below its tier (lib/wallet/subfrostFeePatch.ts) —
//                     we declare the rate its estimate says our fee already pays, and gateSignedTx refuses any rewrite.
//                     Nothing is patched onto the provider (test: __tests__/wallet/browser-wallet-signing.test.ts:447).
// UNTESTED HERE: no wallet was exercised from this repo (no browser automation on this machine). Verified = the
// call shapes above match the app's working source; the signing round trip is the operator's canary.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { addressToScript, scriptType } from './address.js';
import { bytesToHex, hexToBytes, concat, equalBytes, bytesToBase64 } from './bytes.js';
import { hash160 } from './ripemd160.js';

const TIMEOUT_MS = 180_000;
function withTimeout(p, ms, what) {
  let t;
  return Promise.race([Promise.resolve(p), new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what}: no answer in ${ms / 1000}s`)), ms); })])
    .finally(() => clearTimeout(t));
}

/** subfrost-app lib/wallet/subfrostFeePatch.ts: the rate the extension's estimate (10 + 68·in + 31·out) says we pay. */
export function declaredFeeRateForSubfrost(totalIn, totalOut, nIn, nOut) {
  if (totalOut > totalIn) return undefined;
  const fee = Number(totalIn - totalOut);
  const vsize = Math.max(1, 10 + 68 * nIn + 31 * nOut);
  const rate = Math.floor((fee / vsize) * 100) / 100;
  if (!(rate >= 1)) return undefined;
  return Math.min(rate, 1000);
}

/** Normalise a reported public key to { compressed?: Uint8Array(33), xonly: Uint8Array(32) }. */
export function normalizePubkey(hex) {
  if (typeof hex !== 'string') throw new Error('wallet gave no public key');
  const b = hexToBytes(hex);
  if (b.length === 33 && (b[0] === 2 || b[0] === 3)) return { compressed: b, xonly: b.slice(1) };
  if (b.length === 32) return { xonly: b };
  throw new Error(`unexpected public key length ${b.length}`);
}

/**
 * PSBT input metadata for a coin at `account` ({ address, publicKey }). Checks that the key really owns the
 * script where that is checkable without curve maths (p2wpkh, p2sh-p2wpkh): a mismatch refuses.
 */
export function inputMetaFor(coin, account) {
  const script = coin.script;
  const kind = scriptType(script);
  const meta = { witnessUtxo: { value: coin.value, script } };
  const pk = normalizePubkey(account.publicKey);
  if (kind === 'p2tr') meta.tapInternalKey = pk.xonly;
  else if (kind === 'p2wpkh') {
    if (!pk.compressed || !equalBytes(hash160(pk.compressed), script.slice(2, 22))) throw new Error(`${account.address}: public key does not own this p2wpkh coin`);
  } else if (kind === 'p2sh') {
    if (!pk.compressed) throw new Error('p2sh coin needs a compressed public key');
    const redeem = concat(Uint8Array.of(0x00, 0x14), hash160(pk.compressed));
    if (!equalBytes(hash160(redeem), script.slice(2, 22))) throw new Error(`${account.address}: not a p2sh-p2wpkh address of this key — unsupported`);
    meta.redeemScript = redeem;
  } else throw new Error(`unsupported coin script type ${kind}`);
  return meta;
}

function account(address, publicKey) {
  const { type, script } = addressToScript(address);
  return { address, publicKey, type, script };
}

/** Pick the alkanes (taproot) account and the payment account from a list; single-address wallets use one for both. */
function pair(alk, pay) {
  return { alkanes: alk, payment: pay || alk };
}

export const WALLETS = [
  {
    id: 'subfrost', name: 'SUBFROST Wallet',
    provider: (w) => (w.subfrost && typeof w.subfrost === 'object' && typeof w.subfrost.requestAccounts === 'function' ? w.subfrost : null),
    async connect(p) {
      const accounts = await withTimeout(p.requestAccounts(), TIMEOUT_MS, 'SUBFROST');
      if (!Array.isArray(accounts) || !accounts.length) throw new Error('SUBFROST returned no account');
      const pk = await withTimeout(p.getPublicKey(), TIMEOUT_MS, 'SUBFROST');
      return pair(account(accounts[0], pk));
    },
    async sign(p, psbt, ctx) {
      const hex = bytesToHex(psbt);
      const rate = declaredFeeRateForSubfrost(ctx.totalIn, ctx.totalOut, ctx.nIn, ctx.nOut);
      // Undeclared, the extension patches the fee to its own tier and the signed tx no longer matches (gateSignedTx
      // would refuse after the popup). Refuse BEFORE the popup instead; the app floors at 1.25 sat/vB for this reason
      // (subfrostFeePatch.ts SUBFROST_MIN_PACKAGE_FEE_RATE). Review finding 7.
      if (rate === undefined) throw new Error('fee rate too low for the SUBFROST Wallet: its fee patch would rewrite this transaction. Use a higher fee rate (≥ 1.25 sat/vB, more with many inputs).');
      const out = await withTimeout(p.signPsbt(hex, { feeRate: rate }), TIMEOUT_MS, 'SUBFROST');
      if (!out) throw new Error('SUBFROST returned nothing');
      return out;
    },
  },
  {
    id: 'unisat', name: 'UniSat',
    provider: (w) => w.unisat || null,
    async connect(p) {
      const accounts = await withTimeout(p.requestAccounts(), TIMEOUT_MS, 'UniSat');
      if (!Array.isArray(accounts) || !accounts.length) throw new Error('UniSat returned no account');
      const pk = await withTimeout(p.getPublicKey(), TIMEOUT_MS, 'UniSat');
      return pair(account(accounts[0], pk));
    },
    async sign(p, psbt, ctx) {
      return withTimeout(p.signPsbt(bytesToHex(psbt), { autoFinalized: true, toSignInputs: ctx.inputOwners.map((a, index) => ({ index, address: a })) }), TIMEOUT_MS, 'UniSat');
    },
  },
  {
    id: 'oyl', name: 'OYL',
    provider: (w) => w.oyl || null,
    async connect(p) {
      const a = await withTimeout(p.getAddresses(), TIMEOUT_MS, 'OYL');
      if (!a || !a.taproot) throw new Error('OYL returned no taproot address');
      return pair(account(a.taproot.address, a.taproot.publicKey), a.nativeSegwit ? account(a.nativeSegwit.address, a.nativeSegwit.publicKey) : null);
    },
    async sign(p, psbt) {
      const r = await withTimeout(p.signPsbt({ psbt: bytesToHex(psbt), finalize: false, broadcast: false }), TIMEOUT_MS, 'OYL');
      if (!r || !r.psbt) throw new Error('OYL returned no PSBT');
      return r.psbt;
    },
  },
  {
    id: 'xverse', name: 'Xverse',
    provider: (w) => (w.XverseProviders && w.XverseProviders.BitcoinProvider) || null,
    async connect(p) {
      const r = await withTimeout(p.request('getAccounts', { purposes: ['ordinals', 'payment'] }), TIMEOUT_MS, 'Xverse');
      const list = (r && r.result) || [];
      const ord = list.find((x) => x.purpose === 'ordinals');
      const pay = list.find((x) => x.purpose === 'payment');
      if (!ord) throw new Error('Xverse returned no ordinals (taproot) account');
      return pair(account(ord.address, ord.publicKey), pay ? account(pay.address, pay.publicKey) : null);
    },
    async sign(p, psbt, ctx) {
      const signInputs = {};
      ctx.inputOwners.forEach((a, i) => { (signInputs[a] = signInputs[a] || []).push(i); });
      const r = await withTimeout(p.request('signPsbt', { psbt: bytesToBase64(psbt), signInputs, broadcast: false }), TIMEOUT_MS, 'Xverse');
      if (!r || !r.result || !r.result.psbt) throw new Error(`Xverse signing failed: ${JSON.stringify((r && r.error) || r)}`);
      return r.result.psbt;
    },
  },
  {
    id: 'leather', name: 'Leather',
    provider: (w) => w.LeatherProvider || null,
    async connect(p) {
      const r = await withTimeout(p.request('getAddresses'), TIMEOUT_MS, 'Leather');
      const list = (r && r.result && r.result.addresses) || [];
      const tr = list.find((x) => x.symbol === 'BTC' && x.type === 'p2tr');
      const wp = list.find((x) => x.symbol === 'BTC' && x.type === 'p2wpkh');
      if (!tr) throw new Error('Leather returned no taproot address');
      return pair(account(tr.address, tr.publicKey), wp ? account(wp.address, wp.publicKey) : null);
    },
    async sign(p, psbt, ctx) {
      const r = await withTimeout(p.request('signPsbt', { hex: bytesToHex(psbt), signAtIndex: ctx.inputOwners.map((_, i) => i), broadcast: false }), TIMEOUT_MS, 'Leather');
      if (!r || !r.result || !r.result.hex) throw new Error('Leather returned no PSBT');
      return r.result.hex;
    },
  },
];

export function detectWallets(win) {
  return WALLETS.filter((w) => { try { return !!w.provider(win); } catch { return false; } });
}
