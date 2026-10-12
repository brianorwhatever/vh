import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifySignature } from '../src/ed25519.ts';
const directory = new URL('../../../vectors/ed25519/', import.meta.url);
const reject = new Set(['low_order_A', 'low_order_R', 'non_canonical_A', 'non_canonical_R', 'low_order_residue']);
test('CCTV independent point corpus (including mixed-order positive controls)', () => {
  const vectors = JSON.parse(readFileSync(new URL('cctv.json', directory), 'utf8'));
  for (const v of vectors) {
    const expected = !(v.flags ?? []).some((f: string) => reject.has(f));
    assert.equal(verifySignature(Buffer.from(v.key, 'hex'), Buffer.from(v.msg), Buffer.from(v.sig, 'hex')), expected, `CCTV ${v.number}: ${v.flags}`);
  }
});
test('Wycheproof independent scalar, encoding and ordinary signature corpus', () => {
  const corpus = JSON.parse(readFileSync(new URL('wycheproof.json', directory), 'utf8'));
  for (const g of corpus.testGroups) for (const v of g.tests) {
    assert.equal(verifySignature(Buffer.from(g.publicKey.pk, 'hex'), Buffer.from(v.msg, 'hex'), Buffer.from(v.sig, 'hex')), v.result === 'valid', `Wycheproof ${v.tcId}: ${v.comment}`);
  }
});
