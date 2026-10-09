import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  base58btcDecode,
  base58btcEncode,
  canonicalize,
  createLog,
  createProof,
  hashB58,
  keyHash,
  resolve,
  signerFromSeed,
  updateLog,
  verifyProof,
  witnessProof,
} from "../src/index.ts";

const vectors = JSON.parse(readFileSync(new URL("../../../vectors/primitives.json", import.meta.url), "utf8"));
const seed = (n: number) => n.toString(16).padStart(2, "0").repeat(32);
const NOW = "2026-06-01T00:00:00Z";

test("base58btc round-trips, including leading zeros", () => {
  for (const bytes of [[], [0], [0, 0, 1], [255, 254, 253], [...Array(34).keys()]]) {
    const encoded = base58btcEncode(Uint8Array.from(bytes));
    assert.deepEqual([...base58btcDecode(encoded)!], bytes);
  }
  assert.equal(base58btcDecode("0OIl"), null);
});

test("JCS primitive vectors", () => {
  for (const v of vectors.jcs) assert.equal(canonicalize(JSON.parse(v.text)), v.output);
});

test("hash and key-hash vectors", () => {
  for (const v of vectors.hash) assert.equal(hashB58(v.data), v.output);
  for (const v of vectors.keyHash) assert.equal(keyHash(v.multikey), v.output);
  for (const v of vectors.multikey) assert.equal(signerFromSeed(v.seed).multikey, v.multikey);
});

test("eddsa-jcs-2022 proofs are deterministic and tamper-evident", () => {
  for (const v of vectors.sign) {
    const proof = createProof(v.document, v.seed, v.created ? { created: v.created } : {});
    assert.deepEqual(proof, v.proof);
    assert.equal(verifyProof(v.document, proof), true);
    assert.equal(verifyProof({ ...v.document, x: 1 }, proof), false);
  }
});

test("create, update and resolve a pre-rotated, witnessed log", () => {
  const [k1, k2, w] = [seed(1), seed(2), seed(3)];
  const witnessId = `did:key:${signerFromSeed(w).multikey}`;
  const created = createLog({
    state: { id: "example:{SCID}" },
    parameters: {
      updateKeys: [signerFromSeed(k1).multikey],
      nextKeyHashes: [keyHash(signerFromSeed(k2).multikey)],
      witness: { threshold: 1, witnesses: [{ id: witnessId }] },
    },
    versionTime: "2026-01-01T00:00:00Z",
    signers: [k1],
  });
  assert.match(created.scid, /^Qm/);
  assert.equal(JSON.parse(created.log).state.id, `example:${created.scid}`);

  const updated = updateLog({
    log: created.log,
    state: { id: `example:${created.scid}`, name: "two" },
    parameters: { updateKeys: [signerFromSeed(k2).multikey], nextKeyHashes: [] },
    versionTime: "2026-01-02T00:00:00Z",
    signers: [k2],
  });
  assert.match(updated.versionId, /^2-Qm/);

  const witness = [{ versionId: updated.versionId, proof: [witnessProof(updated.versionId, w)] }];
  const result = resolve({ log: updated.log, witness, now: NOW });
  assert.equal(result.valid, true);
  if (!result.valid) return;
  assert.equal(result.state.name, "two");
  assert.equal(result.metadata.scid, created.scid);
  assert.equal(result.error, null);

  const unwitnessed = resolve({ log: updated.log, now: NOW });
  assert.equal(unwitnessed.valid, false);
  if (!unwitnessed.valid) assert.equal(unwitnessed.error.code, "witness-threshold-not-met");
});

test("a later entry signed by an unauthorised key leaves the earlier entries valid", () => {
  const { log, scid } = createLog({
    state: { id: "example:{SCID}" },
    parameters: { updateKeys: [signerFromSeed(seed(1)).multikey] },
    versionTime: "2026-01-01T00:00:00Z",
    signers: [seed(1)],
  });
  const bad = updateLog({ log, state: { id: scid, v: 2 }, versionTime: "2026-01-02T00:00:00Z", signers: [seed(9)] });
  const result = resolve({ log: bad.log, now: NOW });
  assert.equal(result.valid, true);
  if (!result.valid) return;
  assert.equal(result.firstInvalidVersion, 2);
  assert.equal(result.error?.code, "unauthorized-key");
  assert.deepEqual(result.metadata.warnings.map((w) => w.code), ["invalid-entries"]);
});
