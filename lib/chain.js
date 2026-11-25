// lib/chain.js — every chain read the page makes, all READ-ONLY except `sendRawTransaction` (the user's own
// signed burn, sent only after every gate passed). Transport is injected: the page passes `fetch`, the node
// scripts pass a `tlsfetch-curl` subprocess (the HTTP client these scripts use).
//
// METHODS (names read from source, not guessed):
//   metashrew_height                         core crates/subfrost-fractal/src/track_io.rs:99
//   metashrew_view ["simulate", 0x…, tag]    core subfrost-fractal/src/rpc.rs:55 view_params; frfb.rs:105
//   metashrew_view ["protorunesbyoutpoint"…] subfrost-app lib/alkanes/protorunesByOutpointMV.ts (SoT-1: balances
//                                            are read PER OUTPOINT, never from address-keyed views)
//   esplora_address::utxo [addr]             core crates/subfrost-wallet-cli/src/keysend.rs:242
//   ord_outputs_batch [[outpoints]]          core keysend.rs:210 + subfrost-wallet-common plain_btc_send.rs:305
//                                            (clean iff indexed:true, inscriptions [] and runes {} / [])
//   testmempoolaccept [[hex]]                subfrost-app lib/alkanes/rpc.ts:650 (policy dry run, no broadcast)
//   sendrawtransaction [hex]                 subfrost-app lib/alkanes/rpc.ts:735
//
// CORS (measured 2026-11-25 with tlsfetch-curl, Origin: https://0xcasuwu.github.io):
//   /v4/jsonrpc  — preflight 204 reflects any Origin, but the POST answer carries NO Access-Control-Allow-Origin,
//                  so a browser on another origin cannot read it.
//   /v4/subfrost — per-key Origin allowlist: app.subfrost.io / subfrost.io / localhost:3000 get ACAO on the POST;
//                  github.io (and 127.0.0.1) get 403 {"code":"CORS_BLOCKED"}.
//   → From GitHub Pages the page cannot read the RPC today. The operator must allow the Pages origin on one of these
//     paths. The page detects the failure and says so; it never falls back to another host.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { bytesToHex, hexToBytes, fromUtf8, leToBigInt, concat, utf8 } from './bytes.js';
import { sha256 } from './sha256.js';
import { encodeCellpack } from './alkanes.js';
import { encodeSimulateParcel, decodeSimulateResponse, encodeOutpointWithProtocol, decodeOutpointResponse, pbVarint, encUint128, pbFields } from './protobuf.js';

export class RpcError extends Error {}
export class CorsOrNetworkError extends Error {}

/** Browser transport. A cross-origin read the server does not allow surfaces as a TypeError → CorsOrNetworkError. */
export function fetchTransport(fetchImpl) {
  return async (url, body) => {
    let res;
    try {
      res = await fetchImpl(url, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
        credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', mode: 'cors',
      });
    } catch (e) {
      throw new CorsOrNetworkError(`RPC unreachable from this page (${e && e.message ? e.message : e}). If the RPC is up, `
        + 'it does not allow this origin (CORS).');
    }
    if (!res.ok) throw new RpcError(`RPC HTTP ${res.status}`);
    return res.text();
  };
}

export function makeRpc(url, transport) {
  let id = 0;
  return async function call(method, params) {
    const text = await transport(url, JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }));
    let j;
    try { j = JSON.parse(text); } catch { throw new RpcError(`${method}: answer is not JSON`); }
    if (j && j.error) throw new RpcError(`${method}: ${typeof j.error === 'object' ? (j.error.message || JSON.stringify(j.error)) : j.error}`);
    if (!j || !('result' in j)) throw new RpcError(`${method}: answer has no result`);
    return j.result;
  };
}

function toHeight(v, what) {
  const n = typeof v === 'string' ? Number(v.trim()) : v;
  if (!Number.isSafeInteger(n) || n <= 0) throw new RpcError(`${what}: not a height (${JSON.stringify(v)})`);
  return n;
}

export async function indexerHeight(rpc) { return toHeight(await rpc('metashrew_height', []), 'metashrew_height'); }

/** One alkanes call simulated against live state. A revert THROWS (never read as empty data). */
export async function simulate(rpc, { target, inputs, alkanes = [], blockTag = 'latest', height = 0 }) {
  const calldata = encodeCellpack(target, inputs);
  const parcel = encodeSimulateParcel({ calldata, alkanes, height });
  const hex = await rpc('metashrew_view', ['simulate', '0x' + bytesToHex(parcel), blockTag]);
  if (typeof hex !== 'string') throw new RpcError('simulate: non-string result');
  const res = decodeSimulateResponse(hexToBytes(hex));
  if (res.error) { const e = new RpcError(`simulate reverted: ${res.error}`); e.simulate = res; throw e; }
  if (!res.hasExecution) throw new RpcError('simulate: no execution in the answer');
  return res;
}

export function u128Data(data, what) {
  if (data.length !== 16) throw new RpcError(`${what}: expected 16 bytes, got ${data.length}`);
  return leToBigInt(data);
}

/** Token facts read from the live contract at one tag. */
export async function readToken(rpc, id, blockTag = 'latest') {
  const call = (op) => simulate(rpc, { target: id, inputs: [op], blockTag });
  const [name, symbol, supply, max] = await Promise.all([call(99n), call(100n), call(101n), call(102n)]);
  return {
    name: fromUtf8(name.data),
    symbol: fromUtf8(symbol.data),
    totalSupply: u128Data(supply.data, 'GetTotalSupply'),
    maxSupply: u128Data(max.data, 'GetMaxSupply'),
  };
}

/** Alkanes at one outpoint. `{ empty: true }` = the indexer has no row for it (unknown / unindexed / pre-genesis). */
export async function outpointAlkanes(rpc, txid, vout, blockTag = 'latest') {
  const req = encodeOutpointWithProtocol(txid, vout, 1n);
  const hex = await rpc('metashrew_view', ['protorunesbyoutpoint', '0x' + bytesToHex(req), blockTag]);
  if (typeof hex !== 'string' || !/^(0x)?([0-9a-fA-F]{2})*$/.test(hex)) throw new RpcError(`protorunesbyoutpoint ${txid}:${vout}: malformed answer`);
  const d = decodeOutpointResponse(hexToBytes(hex));
  if (!d.empty) {
    if (!d.outpoint || d.outpoint.txid !== txid.toLowerCase() || d.outpoint.vout !== vout) {
      throw new RpcError(`protorunesbyoutpoint ${txid}:${vout}: answer is for another outpoint`);
    }
  }
  return d;
}

export async function addressUtxos(rpc, address) {
  const r = await rpc('esplora_address::utxo', [address]);
  if (!Array.isArray(r)) throw new RpcError('esplora_address::utxo: not a list');
  return r.map((u) => {
    if (typeof u.txid !== 'string' || !/^[0-9a-f]{64}$/i.test(u.txid) || !Number.isInteger(u.vout) || !Number.isSafeInteger(u.value)) {
      throw new RpcError('esplora_address::utxo: malformed row');
    }
    return {
      txid: u.txid.toLowerCase(), vout: u.vout, value: BigInt(u.value),
      confirmed: !!(u.status && u.status.confirmed), height: u.status && u.status.block_height ? u.status.block_height : 0,
    };
  });
}

/** ord rows keyed "txid:vout". A coin missing from the answer stays absent (= unverified). */
export async function ordOutputs(rpc, outpoints) {
  if (!outpoints.length) return new Map();
  const rows = await rpc('ord_outputs_batch', [outpoints]);
  if (!Array.isArray(rows)) throw new RpcError('ord_outputs_batch: not a list');
  const m = new Map();
  for (const row of rows) if (row && typeof row.outpoint === 'string') m.set(row.outpoint.toLowerCase(), row);
  return m;
}

export async function testMempoolAccept(rpc, hex) {
  const r = await rpc('testmempoolaccept', [[hex]]);
  const first = Array.isArray(r) ? r[0] : null;
  if (!first || typeof first.allowed !== 'boolean') throw new RpcError('testmempoolaccept: no verdict');
  return { allowed: first.allowed, reason: first['reject-reason'], txid: first.txid };
}

export async function sendRawTransaction(rpc, hex) {
  const r = await rpc('sendrawtransaction', [hex]);
  if (typeof r !== 'string' || !/^[0-9a-f]{64}$/i.test(r)) throw new RpcError('sendrawtransaction: no txid in the answer');
  return r.toLowerCase();
}

// ── batched simulate, storage and bytecode views ──────────────────────────────────────────────────────
// alkanes-rs src/lib.rs:59-84 exports the batch view as `multisimluate` (sic). Each parcel runs on its OWN
// state (measured at 977,470: GetTotalSupply → Burn → GetTotalSupply returned the same supply twice), so a batch
// saves rate-limited requests but cannot chain state. A parcel that reverts comes back as an EMPTY response
// (no `execution`) and the batch-level `error` holds the last revert message.
// The keyless /v4/jsonrpc path limits metashrew_view to 20 requests per minute (measured 2026-11-25).


const _lf = (f, b) => concat(pbVarint((f << 3) | 2), pbVarint(b.length), b);
const _id = (id) => concat(_lf(1, encUint128(id.block)), _lf(2, encUint128(id.tx)));

/** calls: [{ target, inputs, alkanes }] → [{ ok, error, data, returned, gasUsed }] in order. */
export async function multiSimulate(rpc, calls, blockTag) {
  const req = concat(...calls.map((c) => _lf(1, encodeSimulateParcel({ calldata: encodeCellpack(c.target, c.inputs), alkanes: c.alkanes || [] }))));
  const hex = await rpc('metashrew_view', ['multisimluate', '0x' + bytesToHex(req), blockTag]);
  if (typeof hex !== 'string') throw new RpcError('multisimluate: non-string result');
  const top = pbFields(hexToBytes(hex));
  const responses = top.filter((f) => f.field === 1);
  const errField = top.find((f) => f.field === 2);
  const batchError = errField ? fromUtf8(errField.value) : '';
  if (responses.length !== calls.length) throw new RpcError(`multisimluate: ${responses.length} answers for ${calls.length} calls`);
  return responses.map((r) => {
    const d = decodeSimulateResponse(r.value);
    const ok = d.hasExecution && !d.error;
    return { ok, error: ok ? '' : (d.error || batchError || 'reverted'), data: d.data, returned: d.alkanes, gasUsed: d.gasUsed };
  });
}

export async function storageAt(rpc, id, path, blockTag) {
  const req = concat(_lf(1, _id(id)), _lf(2, utf8(path)));
  const hex = await rpc('metashrew_view', ['getstorageat', '0x' + bytesToHex(req), blockTag]);
  const f = pbFields(hexToBytes(hex));
  const v = f.find((x) => x.field === 1);
  return v ? v.value : new Uint8Array(0);
}

/** The implementation behind a proxy: /implementation holds two little-endian u128 (block, tx). */
export async function proxyImplementation(rpc, id, blockTag) {
  const v = await storageAt(rpc, id, '/implementation', blockTag);
  if (v.length !== 32) throw new RpcError(`/implementation of ${id.block}:${id.tx} is ${v.length} bytes, not an alkane id`);
  return { block: leToBigInt(v.slice(0, 16)), tx: leToBigInt(v.slice(16)) };
}

export async function bytecodeSha256(rpc, id, blockTag) {
  const hex = await rpc('metashrew_view', ['getbytecode', '0x' + bytesToHex(_lf(1, _id(id))), blockTag]);
  const raw = hexToBytes(hex);
  if (raw.length < 8 || raw[0] !== 0x00 || raw[1] !== 0x61 || raw[2] !== 0x73 || raw[3] !== 0x6d) throw new RpcError('getbytecode: not a wasm module');
  return bytesToHex(sha256(raw));
}
