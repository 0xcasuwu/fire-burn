// test/crosscheck.test.js — (1) GOLDEN VECTOR: mainnet tx 34e20e61… (block 973,307, an app FIRE→BTC swap with the
// same two-stone shifter this page builds: p0 edict [2:77623, 380000000 → shadow 6], 4 outputs). Our decoder reads
// it and our encoder RE-ENCODES it to the exact on-chain OP_RETURN bytes. Fixture fetched read-only with
// `node scripts/crosscheck.js --golden <txid> --save` (esplora_tx::hex). (2) The independent Python decoder
// (~/.claude/skills/alkanes-local-decode) agrees with ours on built burn runestones and on the golden tx — skipped,
// with a message, only when that skill is not on this machine.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from '../scripts/sri.js';
import { DECODER, compare, reencode, burnScript } from '../scripts/crosscheck.js';
import { parseTx } from '../lib/tx.js';
import { hexToBytes, bytesToHex } from '../lib/bytes.js';
import { decodeRunestoneScript, decipherProtostones, decodeCellpack, isOpReturn } from '../lib/alkanes.js';

const GOLDEN = '34e20e61e443bbbdc1a265ec4ed23113be062c3ff4d969714ab874ef052cc7bb';
const golden = parseTx(hexToBytes(readFileSync(join(ROOT, 'test/fixtures', `${GOLDEN}.hex`), 'utf8').trim()));

test('golden mainnet shifter tx: decode gives p0 = [FIRE 380000000 → 6] pointer/refund 0, and re-encodes byte-exact', () => {
  const op = golden.outputs.find((o) => isOpReturn(o.script));
  const rs = decodeRunestoneScript(op.script, golden.outputs.length);
  const stones = decipherProtostones(rs.protocol);
  assert.equal(golden.outputs.length, 4);
  const e = stones[0].edicts[0];
  assert.deepEqual([e.id.block, e.id.tx, e.amount, e.output], [2n, 77623n, 380000000n, 6n]);
  assert.equal(e.output, BigInt(golden.outputs.length + 2), 'shadow(p1) = outputs + 1 + 1');
  assert.deepEqual([stones[0].pointer, stones[0].refund], [0n, 0n]);
  const cp = decodeCellpack(stones[1].message);
  assert.deepEqual([cp.target.block, cp.target.tx, cp.inputs[0]], [4n, 65522n, 13n]);
  assert.equal(bytesToHex(reencode(rs, stones)), bytesToHex(op.script));
});

const haveDecoder = existsSync(DECODER);
test('independent Python decoder agrees on built burn runestones and on the golden tx', { skip: haveDecoder ? false : `decoder skill not found at ${DECODER}` }, () => {
  for (const [amount, outs] of [[1n, 3], [150000000n, 3], [13179173303n, 2], [(1n << 100n) + 7n, 3]]) {
    const r = compare(burnScript(amount, outs), outs + 1);
    assert.deepEqual(r.bad, [], `burn ${amount}`);
  }
  const op = golden.outputs.find((o) => isOpReturn(o.script));
  assert.deepEqual(compare(op.script, golden.outputs.length).bad, []);
});
