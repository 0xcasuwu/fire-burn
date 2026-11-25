// test/trace.test.js — the trace decoder used by scripts/canary-verify.js, on the GOLDEN mainnet trace of
// 34e20e61…:6 (p1 of an app FIRE shifter; fetched read-only at tag 977,471 into test/fixtures) — it is the
// execution evidence that p0's edict delivers EXACTLY N FIRE to p1's call — and on a synthetic FAILURE trace.
// JOURNAL 2026-11-25 created for fire-burn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from '../scripts/sri.js';
import { decodeTrace } from '../scripts/canary-verify.js';
import { hexToBytes, concat } from '../lib/bytes.js';
import { pbVarint, encUint128 } from '../lib/protobuf.js';

const lf = (f, b) => concat(pbVarint((f << 3) | 2), pbVarint(b.length), b);

test('golden trace: the call at shadow vout 6 received exactly [2:77623 × 380000000] and exited SUCCESS', () => {
  const hex = readFileSync(join(ROOT, 'test/fixtures/34e20e61e443bbbdc1a265ec4ed23113be062c3ff4d969714ab874ef052cc7bb.trace6.hex'), 'utf8').trim();
  const ev = decodeTrace(hexToBytes(hex));
  const enter = ev.find((e) => e.kind === 'enter');
  assert.deepEqual([enter.myself.block, enter.myself.tx, enter.inputs[0]], [4n, 65522n, 13n]);
  assert.deepEqual(enter.incoming.map((t) => [t.id.block, t.id.tx, t.value]), [[2n, 77623n, 380000000n]]);
  assert.equal(ev.filter((e) => e.kind === 'exit').at(-1).ok, true);
});

test('synthetic FAILURE exit decodes as not ok (poisoned twin)', () => {
  const ctx = concat(lf(1, concat(lf(1, encUint128(2n)), lf(2, encUint128(77623n)))), lf(3, encUint128(88n)));
  const enter = lf(1, lf(1, concat(pbVarint(8), pbVarint(1), lf(2, lf(1, ctx)))));
  const exit = lf(1, lf(2, concat(pbVarint(8), pbVarint(1))));
  const ev = decodeTrace(concat(enter, exit));
  assert.equal(ev[0].kind, 'enter');
  assert.deepEqual(ev[0].inputs, [88n]);
  assert.equal(ev[1].ok, false);
});
