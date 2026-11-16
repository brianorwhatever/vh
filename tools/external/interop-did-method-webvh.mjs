// Generates did:vh logs with the independent Interop Alliance implementation,
// @interop/did-method-webvh (github.com/interop-alliance/did-method-webvh, the
// `/vh` subpath), as external fixtures for the did:vh harness suite. Every
// did:vh driver must resolve each log to the document, versionId and
// deactivated flag that @interop/did-method-webvh itself resolves it to.
//
// Keys are fixed, but the library stamps update and deactivation times itself,
// so regenerating changes the bytes (as with vectors/external/didwebvh-ts).
//
// Run with the package installed somewhere outside this repository:
//   mkdir /tmp/interop && cd /tmp/interop && npm i @interop/did-method-webvh@5.20.0
//   node tools/external/interop-did-method-webvh.mjs /tmp/interop vectors/didvh/external/interop-did-method-webvh
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [pkgDir, out] = process.argv.slice(2);
if (!pkgDir || !out) throw new Error("usage: node interop-did-method-webvh.mjs <dir with node_modules/@interop/did-method-webvh> <output dir>");
const modules = join(pkgDir, "node_modules");
const dist = join(modules, "@interop/did-method-webvh/dist");
const version = JSON.parse(readFileSync(join(modules, "@interop/did-method-webvh/package.json"), "utf8")).version;
const vh = await import(join(dist, "vh.js"));
const lib = await import(join(dist, "index.js"));
const { ed25519 } = await import(join(modules, "@noble/curves/ed25519.js"));

// Deterministic Ed25519 keys, distinct from the repository's own test keys.
function key(name) {
  const secret = createHash("sha256").update(`interop-did-method-webvh-external:${name}`).digest();
  const publicKey = ed25519.getPublicKey(secret);
  const multikey = lib.multibaseEncode(Uint8Array.from([0xed, 0x01, ...publicKey]), lib.MultibaseEncoding.BASE58_BTC);
  const signer = lib.signerFromExternalKey({ publicKeyMultibase: multikey, sign: async ({ data }) => ed25519.sign(data, secret) });
  return { multikey, signer, vm: `did:key:${multikey}#${multikey}` };
}
const K = Object.fromEntries(["k1", "k2", "k3", "wA", "wB"].map((n) => [n, key(n)]));
const CREATED = "2026-03-01T12:00:00Z";

async function witnessEntry(name, versionId) {
  const signDoc = lib.createDocumentSigner(K[name].signer, K[name].vm);
  const proof = await lib.createWitnessProof(async (doc) => ({ proof: (await signDoc(doc)).proof }), versionId, K[name].vm);
  return { versionId, proof: [proof] };
}

mkdirSync(out, { recursive: true });
const scenarios = [];

async function save(name, description, did, log, witnessFile) {
  const text = lib.logToJsonlString(log);
  // The library stamps updates with the current time, so the resolver's clock
  // is set an hour after the last entry rather than to a fixed date.
  const NOW = new Date(Date.parse(log.at(-1).versionTime) + 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const resolved = await vh.resolveDID(did, { didLog: text, ...(witnessFile ? { didWitness: witnessFile } : {}), network: "none" });
  // (resolveDID has no clock option; it uses the current time, which is before NOW.)
  if (resolved.didResolutionMetadata?.error) throw new Error(`@interop/did-method-webvh does not resolve its own ${name} log: ${JSON.stringify(resolved.didResolutionMetadata)}`);
  writeFileSync(join(out, `${name}.jsonl`), text.endsWith("\n") ? text : text + "\n");
  if (witnessFile) writeFileSync(join(out, `${name}.witness.json`), JSON.stringify(witnessFile, null, 2) + "\n");
  scenarios.push({
    name,
    description,
    did,
    now: NOW,
    entries: log.length,
    witness: Boolean(witnessFile),
    expect: {
      didDocument: resolved.didDocument ?? null,
      versionId: resolved.didDocumentMetadata.versionId,
      deactivated: resolved.didDocumentMetadata.deactivated ?? false,
    },
  });
}

const services = (n) => [{ id: `#svc-${n}`, type: "LinkedDomains", serviceEndpoint: `https://example.org/${n}` }];

{
  const created = await vh.createDID({ signer: K.k1.signer, updateKeys: [K.k1.multikey], verificationMethods: [{ type: "Multikey", publicKeyMultibase: K.k3.multikey }], created: CREATED });
  const updated = await vh.updateDID({ log: created.log, signer: K.k1.signer, services: services("files") });
  await save("basic", "Create, then add a service.", created.did, updated.log);
}
{
  const created = await vh.createDID({
    signer: K.k1.signer,
    updateKeys: [K.k1.multikey],
    nextKeyHashes: [await lib.deriveNextKeyHash(K.k2.multikey)],
    watchers: ["https://watcher.example.org"],
    verificationMethods: [{ type: "Multikey", publicKeyMultibase: K.k3.multikey }],
    created: CREATED,
  });
  const second = await vh.updateDID({ log: created.log, signer: K.k2.signer, updateKeys: [K.k2.multikey], nextKeyHashes: [await lib.deriveNextKeyHash(K.k3.multikey)], alsoKnownAs: ["https://example.org/alice"] });
  const third = await vh.updateDID({ log: second.log, signer: K.k3.signer, updateKeys: [K.k3.multikey], nextKeyHashes: [] });
  await save("prerotation", "Pre-rotation through two keys, with watchers.", created.did, third.log);
}
{
  const witness = { threshold: 1, witnesses: [{ id: `did:key:${K.wA.multikey}` }, { id: `did:key:${K.wB.multikey}` }] };
  const created = await vh.createDID({ signer: K.k1.signer, updateKeys: [K.k1.multikey], witness, verificationMethods: [{ type: "Multikey", publicKeyMultibase: K.k3.multikey }], created: CREATED });
  const first = [await witnessEntry("wA", created.log[0].versionId)];
  const updated = await vh.updateDID({ log: created.log, signer: K.k1.signer, alsoKnownAs: ["https://example.org/bob"], witnessProofs: first });
  const file = [...first, await witnessEntry("wB", updated.log.at(-1).versionId)];
  await save("witnessed", "One of two witnesses must approve each entry.", created.did, updated.log, file);
}
{
  const created = await vh.createDID({ signer: K.k1.signer, updateKeys: [K.k1.multikey], verificationMethods: [{ type: "Multikey", publicKeyMultibase: K.k3.multikey }], created: CREATED });
  const updated = await vh.updateDID({ log: created.log, signer: K.k1.signer, alsoKnownAs: ["https://example.org/carol"] });
  const deactivated = await vh.deactivateDID({ log: updated.log, signer: K.k1.signer });
  await save("deactivated", "Created, updated, then deactivated.", created.did, deactivated.log);
}

writeFileSync(
  join(out, "manifest.json"),
  JSON.stringify(
    {
      description: `did:vh logs generated by the independent @interop/did-method-webvh ${version} (tools/external/interop-did-method-webvh.mjs). The library stamps update times itself, so regenerating changes the bytes. The did:vh suite has every did:vh driver resolve each log with didvh-resolve and compares the document, versionId and deactivated with what @interop/did-method-webvh resolves.`,
      source: { package: "@interop/did-method-webvh", version, repository: "https://github.com/interop-alliance/did-method-webvh" },
      scenarios,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${scenarios.length} @interop/did-method-webvh scenarios to ${out}`);
