// Interop driver: JSON Lines requests on stdin, responses on stdout (docs/interop-protocol.md).
import { signerFromSeed } from "./ed25519.ts";
import { hashB58, keyHash } from "./hash.ts";
import { lines } from "./lines.ts";
import { canonicalize } from "./jcs.ts";
import { createDid, DidVhError, locateSrc, parseDidUrl, resolveDid, updateDid } from "./didvh.ts";
import { computeEntryHash, computeScid, createLog, updateLog, witnessProof } from "./log.ts";
import { createProof, verifyProof } from "./proof.ts";
import { resolve } from "./resolve.ts";

type Input = Record<string, any>;

const ops: Record<string, (input: Input) => unknown> = {
  jcs: (i) => ({ output: canonicalize(JSON.parse(i.text)) }),
  hash: (i) => ({ output: hashB58(i.data) }),
  multikey: (i) => ({ multikey: signerFromSeed(i.seed).multikey }),
  "key-hash": (i) => ({ output: keyHash(i.multikey) }),
  scid: (i) => ({ scid: computeScid(i.entry) }),
  "entry-hash": (i) => ({ hash: computeEntryHash(i.entry, i.previousVersionId) }),
  sign: (i) => ({
    proof: createProof(i.document, i.seed, { verificationMethod: i.verificationMethod, created: i.created }),
  }),
  verify: (i) => ({ valid: verifyProof(i.document, i.proof) }),
  create: (i) => createLog({ state: i.state, parameters: i.parameters, versionTime: i.versionTime, signers: i.signers }),
  update: (i) =>
    updateLog({ log: i.log, state: i.state, parameters: i.parameters, versionTime: i.versionTime, signers: i.signers }),
  witness: (i) => ({ proof: witnessProof(i.versionId, i.seed, i.created) }),
  resolve: (i) => resolve(i as any),
  // did:vh (docs/interop-protocol.md, "did:vh operations")
  "didvh-create": (i) =>
    createDid({ document: i.document, parameters: i.parameters, versionTime: i.versionTime, signers: i.signers }),
  "didvh-update": (i) =>
    updateDid({ log: i.log, document: i.document, parameters: i.parameters, versionTime: i.versionTime, signers: i.signers }),
  "didvh-resolve": (i) => resolveDid(i.did, i.options, { now: i.now, remote: i.remote ?? false }),
  "didvh-src": (i) => rejected(() => ({ valid: true, ...locateSrc(i.src) })),
  "didvh-did-url": (i) => rejected(() => ({ valid: true, ...parseDidUrl(i.didUrl) })),
};

/** Runs `fn`, turning a did:vh error into `{valid: false, error}`. */
function rejected(fn: () => object): object {
  try {
    return fn();
  } catch (e) {
    if (e instanceof DidVhError) return { valid: false, error: e.code };
    throw e;
  }
}

for await (const line of lines(process.stdin)) {
  if (line.trim() === "") continue;
  let id: unknown = null;
  let response: unknown;
  try {
    const request = JSON.parse(line);
    id = request.id;
    const op = ops[request.op];
    if (!op) throw new Error(`unknown op ${request.op}`);
    response = { id, ok: true, result: op(request.input ?? {}) };
  } catch (e) {
    response = { id, ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  process.stdout.write(JSON.stringify(response) + "\n");
}
