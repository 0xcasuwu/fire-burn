// lib/bytes.js — byte helpers shared by every module (no dependencies, browser + node).
//
// PURPOSE: hex/base64/concat, little-endian integer writers, Bitcoin CompactSize, and a bounds-checked
// Reader. Every parser in this repo reads through Reader so a truncated input throws instead of reading
// `undefined` as 0 (an empty read must never look like a valid zero).
//
// JOURNAL
//  2026-11-25 created for fire-burn (static FIRE op-88 burn page).

export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex: not a string');
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('hex: invalid');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function u32le(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('u32 out of range');
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

export function u64le(v) {
  let x = BigInt(v);
  if (x < 0n || x >= 1n << 64n) throw new Error('u64 out of range');
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/** Little-endian unsigned integer of any width → BigInt. */
export function leToBigInt(b) {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

/** BigInt → fixed-width little-endian bytes (throws if it does not fit). */
export function bigIntToLe(v, width) {
  let x = BigInt(v);
  if (x < 0n) throw new Error('negative');
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  if (x !== 0n) throw new Error(`value does not fit in ${width} bytes`);
  return out;
}

export function bigIntToBe(v, width) {
  return bigIntToLe(v, width).reverse();
}

export function beToBigInt(b) {
  return leToBigInt(Uint8Array.from(b).reverse());
}

/** Bitcoin CompactSize (varint) */
export function compactSize(n) {
  if (!Number.isInteger(n) || n < 0) throw new Error('compactSize: bad n');
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >>> 8]);
  if (n <= 0xffffffff) return concat(new Uint8Array([0xfe]), u32le(n));
  return concat(new Uint8Array([0xff]), u64le(n));
}

export class Reader {
  constructor(bytes) { this.b = bytes; this.o = 0; }
  get remaining() { return this.b.length - this.o; }
  bytes(n) {
    if (!Number.isInteger(n) || n < 0 || this.o + n > this.b.length) throw new Error('read past end');
    const s = this.b.slice(this.o, this.o + n);
    this.o += n;
    return s;
  }
  u8() { return this.bytes(1)[0]; }
  u32() { const s = this.bytes(4); return (s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24)) >>> 0; }
  u64() { return leToBigInt(this.bytes(8)); }
  compactSize() {
    const f = this.u8();
    if (f < 0xfd) return f;
    if (f === 0xfd) { const s = this.bytes(2); return s[0] | (s[1] << 8); }
    if (f === 0xfe) return this.u32();
    const v = this.u64();
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('compactSize too large');
    return Number(v);
  }
  varBytes() { return this.bytes(this.compactSize()); }
}

export function utf8(s) { return new TextEncoder().encode(s); }
export function fromUtf8(b) { return new TextDecoder('utf-8', { fatal: true }).decode(b); }

export function bytesToBase64(b) {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

export function base64ToBytes(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s.trim())) throw new Error('base64: invalid');
  const bin = atob(s.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Reverse a copy (txid display order ↔ internal order). */
export function reversed(b) { return Uint8Array.from(b).reverse(); }
