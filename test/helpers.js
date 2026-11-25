// test/helpers.js — shared fixtures: random accounts/coins (generated per run, never hardcoded), an in-memory
// chain that answers the RPC methods lib/chain.js calls, and fake wallets (honest + malicious).
//
// The fake chain's FIRE contract implements the reviewed burn() of 4:512 (lib/burn.js REVIEWED_IMPLS note):
// refuse when no FIRE / zero, decrease supply (underflow reverts), return every non-FIRE entry.
// Public keys here are random 33-byte strings, not curve points: nothing in this repo verifies signatures (the
// node's testmempoolaccept does that on mainnet), so only their hash160 matters.
// JOURNAL 2026-11-25 created for fire-burn.

import { randomBytes } from 'node:crypto';
import { concat, bytesToHex, hexToBytes, bigIntToLe, leToBigInt, utf8 } from '../lib/bytes.js';
import { scriptToAddress } from '../lib/address.js';
import { hash160 } from '../lib/ripemd160.js';
import { pbVarint, pbFields, encUint128, decUint128 } from '../lib/protobuf.js';
import { decodeCellpack } from '../lib/alkanes.js';
import { parseTx, txid as computeTxid } from '../lib/tx.js';
import { parsePsbt, createPsbt } from '../lib/psbt.js';
import { sha256 } from '../lib/sha256.js';
import { idKey } from '../lib/route.js';
import { FIRE_KEY } from '../lib/burn.js';

const lf = (f, b) => concat(pbVarint((f << 3) | 2), pbVarint(b.length), b);
const vf = (f, v) => concat(pbVarint(f << 3), pbVarint(v));

export function randTaprootAccount() {
  const outKey = randomBytes(32);
  const address = scriptToAddress(concat(Uint8Array.of(0x51, 0x20), outKey));
  return { address, publicKey: bytesToHex(concat(Uint8Array.of(0x02), randomBytes(32))) };
}
export function randWpkhAccount() {
  const pk = concat(Uint8Array.of(0x03), randomBytes(32));
  return { address: scriptToAddress(concat(Uint8Array.of(0x00, 0x14), hash160(pk))), publicKey: bytesToHex(pk) };
}
export function randP2shWpkhAccount() {
  const pk = concat(Uint8Array.of(0x02), randomBytes(32));
  const redeem = concat(Uint8Array.of(0x00, 0x14), hash160(pk));
  return { address: scriptToAddress(concat(Uint8Array.of(0xa9, 0x14), hash160(redeem), Uint8Array.of(0x87))), publicKey: bytesToHex(pk) };
}
export const randTxid = () => bytesToHex(randomBytes(32));

function encTransfer(id, value) {
  const idMsg = concat(lf(1, encUint128(id.block)), lf(2, encUint128(id.tx)));
  return concat(lf(1, idMsg), lf(2, encUint128(value)));
}
function encSimResponse(r) {
  if (!r.ok) return new Uint8Array(0); // a reverted parcel in a batch: empty SimulateResponse
  const exec = concat(...r.returned.map((t) => lf(1, encTransfer(t.id, t.value))), r.data.length ? lf(3, r.data) : new Uint8Array(0));
  return concat(lf(1, exec), vf(2, 1000n));
}
function encOutpointResponse(txid, vout, entries) {
  const items = entries.map((e) => {
    const rid = concat(lf(1, encUint128(e.id.block)), lf(2, encUint128(e.id.tx)));
    return lf(1, concat(lf(1, lf(1, rid)), lf(2, encUint128(e.amount))));
  });
  const sheet = lf(1, concat(...items));
  const op = lf(2, concat(lf(1, hexToBytes(txid).reverse()), vf(2, vout)));
  return concat(sheet, op);
}

/** In-memory chain. `coins`: [{ address, txid, vout, value, height, alkanes?: [{id, amount}] | 'empty', ord?: row }] */
export function fakeChain(opts) {
  const st = {
    height: opts.height ?? 977470,
    supply: opts.supply ?? 19430999055978n,
    maxSupply: opts.maxSupply ?? 210000000000000n,
    name: opts.name ?? 'FIRE',
    impl: opts.impl ?? { block: 4n, tx: 512n },
    bytecode: opts.bytecode ?? concat(Uint8Array.of(0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0), randomBytes(64)),
    coins: opts.coins || [],
    ordDown: !!opts.ordDown,
    mempool: opts.mempool || ((hex) => ({ allowed: true })),
    calls: [],
    burnBehaviour: opts.burnBehaviour || 'reviewed',
  };
  const fireCall = (calldata, alkanes) => {
    const cp = decodeCellpack(calldata);
    if (cp.target.block !== 2n || cp.target.tx !== 77623n) return { ok: false, error: 'unknown alkane' };
    const op = cp.inputs[0];
    if (op === 99n) return { ok: true, returned: [], data: utf8(st.name) };
    if (op === 100n) return { ok: true, returned: [], data: utf8('FIRE') };
    if (op === 101n) return { ok: true, returned: [], data: bigIntToLe(st.supply, 16) };
    if (op === 102n) return { ok: true, returned: [], data: bigIntToLe(st.maxSupply, 16) };
    if (op === 88n) {
      const fire = alkanes.filter((t) => idKey(t.id) === FIRE_KEY).reduce((s, t) => s + t.value, 0n);
      if (fire === 0n) return { ok: false, error: 'no FIRE tokens to burn' };
      if (st.burnBehaviour === 'half') { // poisoned contract: burns half, returns half
        return { ok: true, returned: [{ id: { block: 2n, tx: 77623n }, value: fire / 2n }], data: new Uint8Array(0) };
      }
      if (st.burnBehaviour === 'no-underflow') return { ok: true, returned: [], data: new Uint8Array(0) };
      if (fire > st.supply) return { ok: false, error: 'overflow' };
      return { ok: true, returned: alkanes.filter((t) => idKey(t.id) !== FIRE_KEY), data: new Uint8Array(0) };
    }
    return { ok: false, error: 'Unrecognized opcode' };
  };
  const parseParcel = (b) => {
    const f = pbFields(b);
    const alkanes = f.filter((x) => x.field === 1).map((x) => {
      const t = pbFields(x.value);
      const idf = pbFields(t.find((y) => y.field === 1).value);
      return { id: { block: decUint128(idf.find((y) => y.field === 1).value), tx: decUint128(idf.find((y) => y.field === 2).value) }, value: decUint128(t.find((y) => y.field === 2).value) };
    });
    return { alkanes, calldata: f.find((x) => x.field === 5).value };
  };
  const coinAt = (txid, vout) => st.coins.find((c) => c.txid === txid && c.vout === vout);
  const rpc = async (method, params) => {
    st.calls.push(method + (method === 'metashrew_view' ? ':' + params[0] : ''));
    if (method === 'metashrew_height') return String(st.height);
    if (method === 'metashrew_view') {
      const [name, hex] = params;
      const req = hexToBytes(hex);
      if (name === 'multisimluate') {
        const res = pbFields(req).filter((x) => x.field === 1).map((x) => { const p = parseParcel(x.value); return fireCall(p.calldata, p.alkanes); });
        const errs = res.filter((r) => !r.ok);
        return '0x' + bytesToHex(concat(...res.map((r) => lf(1, encSimResponse(r))), errs.length ? lf(2, utf8(errs.at(-1).error)) : new Uint8Array(0)));
      }
      if (name === 'getstorageat') {
        const f = pbFields(req);
        const path = new TextDecoder().decode(f.find((x) => x.field === 2).value);
        if (path === '/implementation') return '0x' + bytesToHex(lf(1, concat(bigIntToLe(st.impl.block, 16), bigIntToLe(st.impl.tx, 16))));
        return '0x';
      }
      if (name === 'getbytecode') return '0x' + bytesToHex(st.bytecode);
      if (name === 'protorunesbyoutpoint') {
        const f = pbFields(req);
        const txid = bytesToHex(f.find((x) => x.field === 1).value.slice().reverse());
        const vout = Number(f.find((x) => x.field === 2).value);
        const c = coinAt(txid, vout);
        if (!c || c.alkanes === 'empty') return '0x';
        return '0x' + bytesToHex(encOutpointResponse(txid, vout, c.alkanes || []));
      }
      throw new Error(`fake: view ${name}`);
    }
    if (method === 'esplora_address::utxo') {
      return st.coins.filter((c) => c.address === params[0]).map((c) => ({ txid: c.txid, vout: c.vout, value: Number(c.value), status: { confirmed: c.height > 0, block_height: c.height || undefined } }));
    }
    if (method === 'ord_outputs_batch') {
      if (st.ordDown) throw new Error('ord_outputs_batch: upstream unavailable');
      return params[0].map((op) => {
        const [t, v] = op.split(':');
        const c = coinAt(t, Number(v));
        return c && c.ord !== undefined ? { outpoint: op, ...c.ord } : { outpoint: op, indexed: true, inscriptions: [], runes: {} };
      }).filter((r) => r.outpoint);
    }
    if (method === 'testmempoolaccept') { const tx = parseTx(hexToBytes(params[0][0])); return [{ txid: computeTxid(tx), ...st.mempool(params[0][0]) }]; }
    if (method === 'sendrawtransaction') return computeTxid(parseTx(hexToBytes(params[0])));
    throw new Error(`fake: method ${method}`);
  };
  rpc.state = st;
  rpc.bytecodeSha = bytesToHex(sha256(st.bytecode));
  return rpc;
}

/** A wallet adapter that "signs" by attaching well-formed but fake signatures (nothing here verifies them). */
export function fakeWallet(accounts, { tamper } = {}) {
  return {
    id: 'fake', name: 'Fake',
    provider: () => ({}),
    async connect() { return accounts; },
    async sign(_p, psbtBytes) {
      const parsed = parsePsbt(psbtBytes);
      const tx = { ...parsed.tx };
      if (tamper === 'fee') tx.outputs = tx.outputs.map((o, i) => (i === 1 ? { ...o, value: o.value - 500n } : o));
      const metas = parsed.inputs.map((inp) => {
        const s = inp.witnessUtxo.script;
        const extra = [];
        if (tamper !== 'unsigned') {
          // shape-valid signatures: 64-byte schnorr (SIGHASH_DEFAULT); DER-framed ECDSA ending SIGHASH_ALL (0x01)
          if (s[0] === 0x51) extra.push({ key: Uint8Array.of(0x13), value: tamper === 'anyonecanpay' ? concat(randomBytes(64), Uint8Array.of(0x83)) : randomBytes(64) });
          else extra.push({ key: concat(Uint8Array.of(0x02), Uint8Array.of(0x02), randomBytes(32)), value: concat(Uint8Array.of(0x30), randomBytes(69), Uint8Array.of(tamper === 'anyonecanpay' ? 0x83 : 0x01)) });
        }
        return { witnessUtxo: inp.witnessUtxo, tapInternalKey: inp.tapInternalKey, redeemScript: inp.redeemScript, extra };
      });
      return bytesToHex(createPsbt(tx, metas));
    },
  };
}

export { leToBigInt };
