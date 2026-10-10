import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

export function workloads(root) {
  const generation = JSON.parse(readFileSync(new URL('vectors/generation.json', root))).scenarios;
  const primitives = JSON.parse(readFileSync(new URL('vectors/primitives.json', root)));
  const minimal = generation.find(s => s.name === 'minimal');
  const witnessed = generation.find(s => s.name === 'witnessed');
  const signature = primitives.sign[0];
  const genesis = minimal.steps[0];
  const resolution = (id, title, scenario) => ({
    id, title, description: `${scenario.steps.length} entries, ${scenario.name === 'witnessed' ? 'with witness proofs' : 'without witnesses'}; full history verification.`,
    op: 'resolve', input: { log: scenario.log, now: scenario.resolve.now, ...(scenario.witnessFile ? { witness: scenario.witnessFile } : {}) },
    check(result) {
      assert.equal(result.valid, true);
      assert.equal(result.error, null);
      assert.equal(result.firstInvalidVersion, null);
      assert.deepEqual(result.state, scenario.resolve.state);
      assert.equal(result.metadata.versionId, scenario.steps.at(-1).expect.versionId);
    },
  });
  return [
    resolution('resolve', 'Resolve · 2 entries', minimal),
    resolution('witness', 'Resolve · 4 + witnesses', witnessed),
    {
      id: 'create', title: 'Create · 1 entry', description: 'Canonicalize, derive the SCID and entry hash, and sign a genesis entry.',
      op: 'create', input: genesis.input,
      check(result) {
        assert.equal(result.scid, genesis.expect.scid);
        assert.equal(result.versionId, genesis.expect.versionId);
        assert.deepEqual(JSON.parse(result.log), genesis.expect.line);
      },
    },
    {
      id: 'sign', title: 'Sign · proof', description: 'Canonicalize a document and proof configuration, hash both, and sign with Ed25519.',
      op: 'sign', input: { document: signature.document, seed: signature.seed, created: signature.created },
      check(result) { assert.deepEqual(result.proof, signature.proof); },
    },
  ];
}
