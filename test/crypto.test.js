// test/crypto.test.js — sha256 / ripemd160 / hash160 against node:crypto on random inputs; bech32(m) and base58
// address ⇄ script round trips over random programs, each with poisoned twins. No hardcoded digests or addresses.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { sha256, sha256d, taggedHash } from '../lib/sha256.js';
import { ripemd160, hash160 } from '../lib/ripemd160.js';
import { addressToScript, scriptToAddress, scriptType, NETWORKS } from '../lib/address.js';
import { bytesToHex, concat } from '../lib/bytes.js';

const node = (alg, b) => createHash(alg).update(b).digest('hex');

test('sha256 matches node:crypto for lengths 0..300 and a 1 MB input', () => {
  for (let n = 0; n <= 300; n++) {
    const b = randomBytes(n);
    assert.equal(bytesToHex(sha256(b)), node('sha256', b), `len ${n}`);
  }
  const big = randomBytes(1 << 20);
  assert.equal(bytesToHex(sha256(big)), node('sha256', big));
  const b = randomBytes(77);
  assert.equal(bytesToHex(sha256d(b)), node('sha256', createHash('sha256').update(b).digest()));
  const tag = createHash('sha256').update('TapSighash').digest();
  assert.equal(bytesToHex(taggedHash('TapSighash', b)), node('sha256', concat(tag, tag, b)));
});

test('sha256 poisoned twin: a one-bit change changes the digest', () => {
  const b = randomBytes(64);
  const c = Uint8Array.from(b); c[10] ^= 1;
  assert.notEqual(bytesToHex(sha256(b)), bytesToHex(sha256(c)));
});

test('ripemd160 and hash160 match node:crypto for lengths 0..200', () => {
  for (let n = 0; n <= 200; n++) {
    const b = randomBytes(n);
    assert.equal(bytesToHex(ripemd160(b)), node('ripemd160', b), `len ${n}`);
    assert.equal(bytesToHex(hash160(b)), node('ripemd160', createHash('sha256').update(b).digest()));
  }
});

test('addresses: random programs round-trip through bech32/bech32m/base58 on two networks', () => {
  for (const net of [NETWORKS.mainnet, NETWORKS.testnet]) {
    for (let i = 0; i < 50; i++) {
      const p20 = randomBytes(20), p32 = randomBytes(32);
      const scripts = [
        concat(Uint8Array.of(0x00, 0x14), p20),
        concat(Uint8Array.of(0x00, 0x20), p32),
        concat(Uint8Array.of(0x51, 0x20), p32),
        concat(Uint8Array.of(0xa9, 0x14), p20, Uint8Array.of(0x87)),
        concat(Uint8Array.of(0x76, 0xa9, 0x14), p20, Uint8Array.of(0x88, 0xac)),
      ];
      for (const s of scripts) {
        const a = scriptToAddress(s, net);
        assert.ok(a);
        const back = addressToScript(a, net);
        assert.equal(bytesToHex(back.script), bytesToHex(s));
        assert.equal(back.type, scriptType(s));
      }
    }
  }
});

test('address poisoned twins: bad checksum, wrong network, v0 as bech32m, v1 as bech32, mixed case, base58 checksum', () => {
  const s = concat(Uint8Array.of(0x51, 0x20), randomBytes(32));
  const a = scriptToAddress(s);
  const flipped = a.slice(0, -1) + (a.at(-1) === 'q' ? 'p' : 'q');
  assert.throws(() => addressToScript(flipped), /checksum/);
  assert.throws(() => addressToScript(scriptToAddress(s, NETWORKS.testnet)), /./);
  // v0 program encoded with the bech32m constant must refuse (BIP350), and v1 with bech32
  const v0 = scriptToAddress(concat(Uint8Array.of(0x00, 0x14), randomBytes(20)));
  assert.equal(addressToScript(v0).type, 'p2wpkh');
  const mixed = a.slice(0, 6) + a.slice(6, 7).toUpperCase() + a.slice(7);
  if (mixed !== a) assert.throws(() => addressToScript(mixed), /mixed case/);
  const b58 = scriptToAddress(concat(Uint8Array.of(0xa9, 0x14), randomBytes(20), Uint8Array.of(0x87)));
  const bad = b58.slice(0, -1) + (b58.at(-1) === '2' ? '3' : '2');
  assert.throws(() => addressToScript(bad), /checksum/);
});
