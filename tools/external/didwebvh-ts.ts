// Generates did:webvh logs with the independent didwebvh-ts implementation, as
// external fixtures for the `external` harness suite. VH-Log was extracted from
// did:webvh, so both share SCID derivation, entry hashing, eddsa-jcs-2022
// proofs, pre-rotation key hashes and witness proofs.
//
// Run from a didwebvh-ts checkout (it imports the checkout's sources):
//   cd /path/to/didwebvh-ts && pnpm install
//   bun /path/to/vh/tools/external/didwebvh-ts.ts /path/to/vh/vectors/external/didwebvh-ts
import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const checkout = process.cwd();
const out = process.argv[2];
if (!out) throw new Error("usage: bun didwebvh-ts.ts <output dir>");

const { createDID, deactivateDID, resolveDIDFromLog, updateDID } = await import(join(checkout, "src/method.ts"));
const { deriveNextKeyHash } = await import(join(checkout, "src/utils/crypto.ts"));
const { signWitnessProofEntry } = await import(join(checkout, "src/witness.ts"));
const { createTestDIDDocument, createTestSigner, generateTestVerificationMethod, TestCryptoImplementation } = await import(
  join(checkout, "test/utils.ts")
);

mkdirSync(out, { recursive: true });
const scenarios: { name: string; description: string; entries: number; witness: boolean }[] = [];

async function save(name: string, description: string, log: any[], verifier: any, witness?: any[]) {
  const resolved = await resolveDIDFromLog(log, { verifier, ...(witness ? { witnessProofs: witness } : {}) });
  if (!resolved.didDocument && !resolved.didDocumentMetadata?.deactivated) {
    throw new Error(`didwebvh-ts does not resolve its own ${name} log: ${JSON.stringify(resolved.didResolutionMetadata)}`);
  }
  writeFileSync(join(out, `${name}.jsonl`), log.map((e) => JSON.stringify(e)).join("\n") + "\n");
  if (witness) writeFileSync(join(out, `${name}.witness.json`), JSON.stringify(witness, null, 2) + "\n");
  scenarios.push({ name, description, entries: log.length, witness: Boolean(witness) });
}

const key = () => generateTestVerificationMethod();
const day = (n: number) => `2026-01-0${n}T00:00:00Z`;

{
  const [k1, k2] = [await key(), await key()];
  const verifier = new TestCryptoImplementation({ verificationMethod: k1 });
  let { log } = await createDID({ address: "example.com", signer: createTestSigner(k1), updateKeys: [k1.publicKeyMultibase], didDocument: createTestDIDDocument(k1), created: day(1), verifier });
  ({ log } = await updateDID({ log, signer: createTestSigner(k1), updateKeys: [k2.publicKeyMultibase], didDocument: createTestDIDDocument(k2), updated: day(2), verifier }));
  ({ log } = await updateDID({ log, signer: createTestSigner(k2), didDocument: createTestDIDDocument(k2), updated: day(3), verifier, watchers: ["https://watcher.example"] }));
  await save("rotation", "Key rotation without pre-rotation, then a watchers change.", log, verifier);
}

{
  const [k1, k2, k3] = [await key(), await key(), await key()];
  const verifier = new TestCryptoImplementation({ verificationMethod: k1 });
  let { log } = await createDID({ address: "example.com:8443/path", signer: createTestSigner(k1), updateKeys: [k1.publicKeyMultibase], nextKeyHashes: [await deriveNextKeyHash(k2.publicKeyMultibase)], didDocument: createTestDIDDocument(k1), created: day(1), verifier });
  ({ log } = await updateDID({ log, signer: createTestSigner(k2), updateKeys: [k2.publicKeyMultibase], nextKeyHashes: [await deriveNextKeyHash(k3.publicKeyMultibase)], didDocument: createTestDIDDocument(k2), updated: day(2), verifier }));
  ({ log } = await updateDID({ log, signer: createTestSigner(k3), updateKeys: [k3.publicKeyMultibase], nextKeyHashes: [], updated: day(3), verifier }));
  await save("prerotation", "Pre-rotation across two rotations, then turned off.", log, verifier);
}

{
  const k1 = await key();
  const witnesses = [];
  for (let i = 0; i < 2; i++) {
    const w = await key();
    w.id = `did:key:${w.publicKeyMultibase}#${w.publicKeyMultibase}`;
    witnesses.push(w);
  }
  const witnessParam = { threshold: 2, witnesses: witnesses.map((w) => ({ id: `did:key:${w.publicKeyMultibase}` })) };
  const signersByDid = Object.fromEntries(witnesses.map((w) => [`did:key:${w.publicKeyMultibase}`, createTestSigner(w)]));
  const sign = (versionId: string, created: string) =>
    signWitnessProofEntry({ versionId, witnesses: witnessParam.witnesses, witnessSignersByDid: signersByDid, created });
  const verifier = new TestCryptoImplementation({ verificationMethod: k1 });
  let { log } = await createDID({ address: "example.com", signer: createTestSigner(k1), updateKeys: [k1.publicKeyMultibase], witness: witnessParam, didDocument: createTestDIDDocument(k1), created: day(1), verifier });
  const witnessFile = [await sign(log[0].versionId, day(1))];
  ({ log } = await updateDID({ log, signer: createTestSigner(k1), didDocument: createTestDIDDocument(k1), updated: day(2), verifier, witnessProofs: witnessFile }));
  witnessFile.push(await sign(log[1].versionId, day(2)));
  await save("witnessed", "Two-of-two witnesses from genesis; both entries witnessed.", log, verifier, witnessFile);
}

{
  const k1 = await key();
  const verifier = new TestCryptoImplementation({ verificationMethod: k1 });
  let { log } = await createDID({ address: "example.com", signer: createTestSigner(k1), updateKeys: [k1.publicKeyMultibase], didDocument: createTestDIDDocument(k1), created: day(1), verifier });
  ({ log } = await deactivateDID({ log, signer: createTestSigner(k1), verifier }));
  await save("deactivated", "Created, then deactivated.", log, verifier);
}

const commit = execSync("git rev-parse --short HEAD", { cwd: checkout }).toString().trim();
writeFileSync(
  join(out, "manifest.json"),
  JSON.stringify(
    {
      description:
        "did:webvh logs generated by the independent didwebvh-ts implementation (tools/external/didwebvh-ts.ts). Keys are random per run, so regenerating changes every byte. The harness's `external` suite checks each entry's SCID, entry hash, proofs, pre-rotation key hashes and witness proofs with every implementation.",
      source: "https://github.com/decentralized-identity/didwebvh-ts",
      commit,
      generated: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      scenarios,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${scenarios.length} scenarios from didwebvh-ts@${commit}`);
