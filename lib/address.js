// lib/address.js — Bitcoin address ⇄ scriptPubKey (bech32 / bech32m per BIP173/BIP350, base58check P2PKH/P2SH).
//
// PURPOSE: the page turns every address a wallet reports into its scriptPubKey and compares SCRIPTS, never
// strings, when it decides "this output is the user's" (gate 1). Mainnet-only by default (hrp "bc", versions
// 0x00/0x05); tests pass "tb" to exercise the same code with a second network.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

import { concat, equalBytes } from './bytes.js';
import { sha256d } from './sha256.js';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

function polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) throw new Error('convertBits: bad value');
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('convertBits: bad padding');
  return out;
}

function bech32Decode(addr) {
  if (addr.length > 90) throw new Error('bech32: too long');
  const lower = addr.toLowerCase();
  if (addr !== lower && addr !== addr.toUpperCase()) throw new Error('bech32: mixed case');
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) throw new Error('bech32: bad separator');
  const hrp = lower.slice(0, pos);
  const data = [];
  for (const c of lower.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error('bech32: bad char');
    data.push(v);
  }
  const pm = polymod([...hrpExpand(hrp), ...data]);
  const enc = pm === BECH32_CONST ? 'bech32' : pm === BECH32M_CONST ? 'bech32m' : null;
  if (!enc) throw new Error('bech32: bad checksum');
  return { hrp, data: data.slice(0, -6), enc };
}

function bech32Encode(hrp, data, enc) {
  const c = enc === 'bech32m' ? BECH32M_CONST : BECH32_CONST;
  const pm = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ c;
  const chk = [];
  for (let i = 0; i < 6; i++) chk.push((pm >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...chk].map((v) => CHARSET[v]).join('');
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58checkDecode(s) {
  let x = 0n;
  for (const c of s) {
    const v = B58.indexOf(c);
    if (v < 0) throw new Error('base58: bad char');
    x = x * 58n + BigInt(v);
  }
  const bytes = [];
  while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  for (const c of s) { if (c === '1') bytes.unshift(0); else break; }
  const b = Uint8Array.from(bytes);
  if (b.length < 5) throw new Error('base58: too short');
  const payload = b.slice(0, -4);
  if (!equalBytes(sha256d(payload).slice(0, 4), b.slice(-4))) throw new Error('base58: bad checksum');
  return payload;
}

function base58checkEncode(payload) {
  const b = concat(payload, sha256d(payload).slice(0, 4));
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  let s = '';
  while (x > 0n) { s = B58[Number(x % 58n)] + s; x /= 58n; }
  for (const v of b) { if (v === 0) s = '1' + s; else break; }
  return s;
}

export const NETWORKS = {
  mainnet: { hrp: 'bc', p2pkh: 0x00, p2sh: 0x05 },
  testnet: { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 },
};

/** address → { type, script } (throws on anything not a standard address of `net`). */
export function addressToScript(address, net = NETWORKS.mainnet) {
  if (typeof address !== 'string' || !address) throw new Error('address: empty');
  if (address.toLowerCase().startsWith(net.hrp + '1')) {
    const { hrp, data, enc } = bech32Decode(address);
    if (hrp !== net.hrp) throw new Error('address: wrong network');
    const version = data[0];
    const prog = Uint8Array.from(convertBits(data.slice(1), 5, 8, false));
    if (version > 16 || prog.length < 2 || prog.length > 40) throw new Error('address: bad witness program');
    if (version === 0 && enc !== 'bech32') throw new Error('address: v0 must be bech32');
    if (version !== 0 && enc !== 'bech32m') throw new Error('address: v1+ must be bech32m');
    if (version === 0 && prog.length !== 20 && prog.length !== 32) throw new Error('address: bad v0 length');
    const opVersion = version === 0 ? 0 : 0x50 + version;
    const script = concat(Uint8Array.of(opVersion, prog.length), prog);
    let type = 'unknown_witness';
    if (version === 0 && prog.length === 20) type = 'p2wpkh';
    else if (version === 0 && prog.length === 32) type = 'p2wsh';
    else if (version === 1 && prog.length === 32) type = 'p2tr';
    return { type, script };
  }
  const payload = base58checkDecode(address);
  if (payload.length !== 21) throw new Error('address: bad base58 length');
  const h = payload.slice(1);
  if (payload[0] === net.p2pkh) return { type: 'p2pkh', script: concat(Uint8Array.of(0x76, 0xa9, 0x14), h, Uint8Array.of(0x88, 0xac)) };
  if (payload[0] === net.p2sh) return { type: 'p2sh', script: concat(Uint8Array.of(0xa9, 0x14), h, Uint8Array.of(0x87)) };
  throw new Error('address: unknown version byte');
}

/** scriptPubKey → type label (used for size estimates and signer routing). */
export function scriptType(script) {
  const s = script;
  if (s.length === 34 && s[0] === 0x51 && s[1] === 0x20) return 'p2tr';
  if (s.length === 22 && s[0] === 0x00 && s[1] === 0x14) return 'p2wpkh';
  if (s.length === 34 && s[0] === 0x00 && s[1] === 0x20) return 'p2wsh';
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) return 'p2sh';
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac) return 'p2pkh';
  if (s.length > 0 && s[0] === 0x6a) return 'op_return';
  return 'unknown';
}

/** scriptPubKey → address (display only; comparisons use scripts). */
export function scriptToAddress(script, net = NETWORKS.mainnet) {
  const t = scriptType(script);
  if (t === 'p2wpkh' || t === 'p2wsh') return bech32Encode(net.hrp, [0, ...convertBits(script.slice(2), 8, 5, true)], 'bech32');
  if (t === 'p2tr') return bech32Encode(net.hrp, [1, ...convertBits(script.slice(2), 8, 5, true)], 'bech32m');
  if (t === 'p2sh') return base58checkEncode(concat(Uint8Array.of(net.p2sh), script.slice(2, 22)));
  if (t === 'p2pkh') return base58checkEncode(concat(Uint8Array.of(net.p2pkh), script.slice(3, 23)));
  return null;
}

/** P2TR scriptPubKey from a 32-byte x-only output key. */
export function p2trScript(outputKeyX) {
  if (outputKeyX.length !== 32) throw new Error('p2tr: key must be 32 bytes');
  return concat(Uint8Array.of(0x51, 0x20), outputKeyX);
}
