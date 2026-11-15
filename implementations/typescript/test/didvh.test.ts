// did:vh library tests: the reference must reproduce every did:vh vector, and
// the specialisation hook must keep VH-Log and did:vh logs apart.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  createDid,
  createLog,
  DidVhError,
  checkRef,
  parseDid,
  parseDidUrl,
  resolve,
  resolveDid,
  signerFromSeed,
  srcReferences,
  updateDid,
} from "../src/index.ts";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../../vectors/didvh");
const read = (path: string) => JSON.parse(readFileSync(join(VECTORS, path), "utf8"));
const SEED = "11".repeat(32);
const MK = signerFromSeed(SEED).multikey;
const NOW = "2026-06-01T00:00:00Z";

test("resolution vectors", () => {
  for (const file of readdirSync(join(VECTORS, "resolution"))) {
    for (const c of read(`resolution/${file}`).cases) {
      const r = resolveDid(c.input.did, c.input.options, { now: c.input.now, remote: c.input.remote ?? false });
      const meta = r.didResolutionMetadata as Record<string, any>;
      if (c.expect.error) {
        assert.equal(meta.error, c.expect.error, c.name);
        assert.equal(meta.problemDetails.vhLog?.code, c.expect.vhLogError, c.name);
      } else {
        assert.equal(meta.error, undefined, c.name);
        assert.deepEqual(r.didDocument, c.expect.didDocument, c.name);
        assert.deepEqual(r.didDocumentMetadata, c.expect.didDocumentMetadata, c.name);
        assert.equal(meta.didLog, c.expect.didLog, c.name);
        assert.deepEqual(meta.didWitness, c.expect.didWitness, c.name);
      }
    }
  }
});

test("reference, src and DID URL vectors", () => {
  const attempt = (fn: () => object) => {
    try {
      return { valid: true, ...fn() };
    } catch (e) {
      assert.ok(e instanceof DidVhError);
      return { valid: false, error: e.code };
    }
  };
  for (const c of read("ref.json").cases) assert.deepEqual(attempt(() => ({ kind: checkRef(c.ref) })), c.expect, c.name);
  for (const c of read("src.json").cases) assert.deepEqual(attempt(() => srcReferences(c.src)), c.expect, c.name);
  for (const c of read("did-url.json").cases) assert.deepEqual(attempt(() => parseDidUrl(c.didUrl)), c.expect, c.name);
});

test("create, update and resolve a did:vh DID", () => {
  const document = { id: "did:vh:{SCID}", controller: "did:vh:{SCID}" };
  const created = createDid({ document, parameters: { updateKeys: [MK] }, versionTime: "2026-01-01T00:00:00Z", signers: [SEED] });
  assert.equal(parseDid(created.did), created.scid);
  const line = JSON.parse(created.log);
  assert.equal(line.parameters.method, "did:vh:1.0");
  assert.equal("logVersion" in line.parameters, false);
  assert.equal(line.state.controller, created.did);

  const updated = updateDid({ log: created.log, document: { id: created.did, v: 2 }, versionTime: "2026-01-02T00:00:00Z", signers: [SEED] });
  const r = resolveDid(created.did, { didLog: updated.log }, { now: NOW });
  assert.deepEqual(r.didDocument, { id: created.did, v: 2 });
  assert.equal(r.didDocumentMetadata.versionId, updated.versionId);
});

test("VH-Log and did:vh logs are not interchangeable", () => {
  const vh = createLog({ state: { id: "did:vh:{SCID}" }, parameters: { updateKeys: [MK] }, versionTime: "2026-01-01T00:00:00Z", signers: [SEED] });
  const asDid = resolveDid(`did:vh:${vh.scid}`, { didLog: vh.log }, { now: NOW });
  assert.equal("error" in asDid.didResolutionMetadata && asDid.didResolutionMetadata.error, "invalidDid");

  const did = createDid({ document: { id: "did:vh:{SCID}" }, parameters: { updateKeys: [MK] }, versionTime: "2026-01-01T00:00:00Z", signers: [SEED] });
  const asLog = resolve({ log: did.log, now: NOW });
  assert.equal(asLog.valid, false);
  assert.equal(!asLog.valid && asLog.error.code, "unsupported-log-version");
});
