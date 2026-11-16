// Generates the did:vh test vectors in ../vectors/didvh from the TypeScript
// reference implementation. Run: node tools/generate-didvh-vectors.ts
//
// Like the VH-Log vectors, these are consensus vectors: each expected result is
// checked against the reference here, so a vector cannot disagree with it.
// Every invalid-log vector is built so that exactly one check fails.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createDid,
  createProof,
  DID_VH_METHOD,
  keyHash,
  checkRef,
  srcReferences,
  parseDidUrl,
  resolveDid,
  SCID_PLACEHOLDER,
  sealEntry,
  sealGenesis,
  serializeEntry,
  signerFromSeed,
  updateDid,
  witnessProof,
  DidVhError,
} from "../implementations/typescript/src/index.ts";
import type { SealOptions } from "../implementations/typescript/src/log.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "vectors", "didvh");
const SPEC = "https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md";
const PROFILE = "docs/didvh-profile.md";

// ---------------------------------------------------------------- fixtures (same keys as vectors/keys.json)

const seed = (name: string) => createHash("sha256").update(`vh-log-interop:${name}`).digest("hex");
const KEYS = Object.fromEntries(
  ["k1", "k2", "k3", "k4", "k5", "attacker", "wA", "wB", "wC", "wD"].map((n) => [n, seed(n)]),
) as Record<string, string>;
const mk = (name: string) => signerFromSeed(KEYS[name]).multikey;
const did = (name: string) => `did:key:${mk(name)}`;
const kh = (name: string) => keyHash(mk(name));

const NOW = "2026-06-01T00:00:00Z";
const t = (day: number, second = 0) =>
  new Date(Date.UTC(2026, 0, day, 0, 0, second)).toISOString().replace(".000Z", "Z");

type Json = Record<string, unknown>;

/** A minimal DID document for `id`, with one verification method. */
const doc = (id: string, extra: Json = {}) => ({
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  id,
  verificationMethod: [{ id: `${id}#key-1`, type: "Multikey", controller: id, publicKeyMultibase: mk("k5") }],
  assertionMethod: [`${id}#key-1`],
  ...extra,
});

/** Builds a did:vh log line by line; entries are sealed without validation. */
class DidLog {
  entries: Json[] = [];
  scid = "";

  get did() {
    return `did:vh:${this.scid}`;
  }

  genesis(
    parameters: Json = {},
    { state, signers = ["k1"], time = t(1), seal = {} as SealOptions, raw = false } = {} as {
      state?: Json; signers?: string[]; time?: string; seal?: SealOptions; raw?: boolean;
    },
  ): this {
    const params = raw ? parameters : { method: DID_VH_METHOD, scid: SCID_PLACEHOLDER, updateKeys: [mk("k1")], ...parameters };
    const { entry, scid } = sealGenesis(
      { versionId: SCID_PLACEHOLDER, versionTime: time, parameters: params, state: state ?? doc(`did:vh:${SCID_PLACEHOLDER}`) },
      signers.map((s) => KEYS[s]),
      seal,
    );
    this.scid = scid;
    this.entries.push(entry as unknown as Json);
    return this;
  }

  update(
    parameters: Json = {},
    { state, signers = ["k1"], time, seal = {} as SealOptions } = {} as {
      state?: Json; signers?: string[]; time?: string; seal?: SealOptions;
    },
  ): this {
    const n = this.entries.length + 1;
    const prev = this.entries.at(-1)!.versionId as string;
    const entry = sealEntry(
      { versionId: prev, versionTime: time ?? t(n), parameters, state: state ?? doc(this.did, { service: [{ id: `${this.did}#v`, type: "Version", serviceEndpoint: `https://example.com/v${n}` }] }) },
      prev,
      signers.map((s) => KEYS[s]),
      seal,
    );
    this.entries.push(entry as unknown as Json);
    return this;
  }

  /** Mutates the last entry after sealing. */
  tamper(fn: (entry: Json) => void): this {
    fn(this.entries.at(-1)!);
    return this;
  }

  vid(n: number) {
    return this.entries[n - 1].versionId as string;
  }

  state(n: number) {
    return this.entries[n - 1].state as Json;
  }

  get log() {
    return this.entries.map(serializeEntry).join("");
  }
}

const witnessConfig = (threshold: number, ...names: string[]) => ({ threshold, witnesses: names.map((n) => ({ id: did(n) })) });
const witnessFile = (...records: [string, ...string[]][]) =>
  records.map(([versionId, ...ws]) => ({ versionId, proof: ws.map((w) => witnessProof(versionId, KEYS[w])) }));

// ---------------------------------------------------------------- resolution cases

interface Expect {
  /** did:vh error code; absent for a successful resolution. */
  error?: string;
  /** VH-Log error code behind the did:vh error, where there is one. */
  vhLogError?: string;
  didDocument?: unknown;
  didDocumentMetadata?: Json;
  /** Sorted warning codes. */
  warnings?: string[];
  /** didResolutionMetadata.didLog / didWitness, when includeDidLog returned them. */
  didLog?: string;
  didWitness?: unknown[];
}

interface Case {
  name: string;
  description: string;
  spec: string[];
  input: Json;
  expect: Expect;
}

const groups: Record<string, Case[]> = {};
let current: Case[] = [];
function group(name: string, fn: () => void) {
  current = groups[name] = [];
  fn();
}

/**
 * Adds a resolution case and checks it against the reference resolver.
 * For a successful case, the document and metadata are taken from the reference
 * after checking any fields given in `expect`.
 */
function vector(name: string, description: string, spec: string[], input: { did: string; options: Json; remote?: boolean }, expect: Expect) {
  const fullInput = { now: NOW, ...input };
  const result = resolveDid(input.did, input.options, { now: NOW, remote: input.remote ?? false }) as unknown as {
    didResolutionMetadata: Json; didDocument: unknown; didDocumentMetadata: Json;
  };
  const fail = (why: string) => {
    throw new Error(`vector ${name}: ${why}\n${JSON.stringify(result, null, 2)}`);
  };
  const meta = result.didResolutionMetadata;
  const final: Expect = { ...expect };
  if (expect.error) {
    if (meta.error !== expect.error) fail(`expected ${expect.error}, got ${meta.error ?? "success"}`);
    const vh = (meta.problemDetails as Json).vhLog as Json | undefined;
    if ((vh?.code ?? undefined) !== expect.vhLogError) fail(`expected VH-Log error ${expect.vhLogError}, got ${vh?.code}`);
  } else {
    if (meta.error) fail(`unexpected error ${meta.error}`);
    for (const [k, v] of Object.entries(expect.didDocumentMetadata ?? {})) {
      if (JSON.stringify(result.didDocumentMetadata[k]) !== JSON.stringify(v)) fail(`metadata.${k}`);
    }
    if ("didDocument" in expect && JSON.stringify(expect.didDocument) !== JSON.stringify(result.didDocument)) fail("didDocument");
    const warnings = ((meta.warnings as Json[] | undefined) ?? []).map((w) => w.code as string).sort();
    if (expect.warnings && JSON.stringify(expect.warnings) !== JSON.stringify(warnings)) fail("warnings");
    final.didDocument = result.didDocument;
    final.didDocumentMetadata = result.didDocumentMetadata;
    final.warnings = warnings;
    if ("didLog" in meta) final.didLog = meta.didLog as string;
    if ("didWitness" in meta) final.didWitness = meta.didWitness as unknown[];
  }
  current.push({ name, description, spec: spec.map((s) => (s.startsWith("#") ? SPEC + s : s)), input: fullInput, expect: final });
}

const S = {
  id: "#method-specific-identifier",
  file: "#the-did-log-file",
  read: "#read-resolve",
  options: "#didvh-resolution-options",
  refs: "#the-srclog-and-srcwitness-options",
  src: "#the-src-did-url-parameter",
  results: "#results-of-processing-the-log",
  algo: "#resolution-algorithm",
  meta: "#did-resolution-metadata",
  deact: "#deactivate-revoke",
  params: "#didvh-did-method-parameters",
  witnesses: "#did-witnesses",
};

group("basic", () => {
  const b = new DidLog().genesis();
  vector("genesis", "A one-entry did:vh log, passed directly.", [S.read, S.meta], { did: b.did, options: { didLog: b.log } },
    { didDocument: b.state(1), didDocumentMetadata: { versionId: b.vid(1), deactivated: false, ttl: 3600, watchers: [] } });

  const u = new DidLog().genesis({ ttl: 300, watchers: ["https://watcher.example/{SCID}"] }).update().update();
  const opts = { didLog: u.log };
  vector("latest", "Three entries; the latest DID document is returned.", [S.read, S.meta], { did: u.did, options: opts },
    { didDocument: u.state(3), didDocumentMetadata: { versionId: u.vid(3), created: t(1), updated: t(3), ttl: 300 } });
  vector("version-number", "versionNumber selects an earlier version; updated still reflects the log.", [S.read, S.meta],
    { did: u.did, options: { ...opts, versionNumber: 2 } }, { didDocument: u.state(2), didDocumentMetadata: { versionId: u.vid(2), updated: t(3) } });
  vector("version-id", "versionId selects the first version.", [S.read], { did: u.did, options: { ...opts, versionId: u.vid(1) } },
    { didDocument: u.state(1) });
  vector("version-time", "versionTime selects the version active at that time.", [S.read], { did: u.did, options: { ...opts, versionTime: t(2, 30) } },
    { didDocument: u.state(2) });
  vector("version-number-not-found", "A versionNumber past the end of the log.", [S.meta], { did: u.did, options: { ...opts, versionNumber: 9 } },
    { error: "notFound", vhLogError: "not-found" });
  vector("version-id-not-found", "A versionId not in the log.", [S.meta], { did: u.did, options: { ...opts, versionId: "9-QmNotThere" } },
    { error: "notFound", vhLogError: "not-found" });
  vector("version-time-before-creation", "A versionTime before the first entry.", [S.meta], { did: u.did, options: { ...opts, versionTime: "2025-12-31T00:00:00Z" } },
    { error: "notFound", vhLogError: "not-found" });
  vector("unknown-option-ignored", "Options this resolver does not know (such as accept) are ignored.", [PROFILE + "#5-resolution"],
    { did: u.did, options: { ...opts, accept: "application/did+json" } }, { didDocument: u.state(3) });
  vector("min-copies-one", "minCopies 1 is met by the log passed directly.", [S.options], { did: u.did, options: { ...opts, minCopies: 1 } },
    { didDocument: u.state(3) });
  vector("min-copies-two", "minCopies 2 cannot be met without watchers.", [S.meta], { did: u.did, options: { ...opts, minCopies: 2 } },
    { error: "insufficientCopies", vhLogError: "min-copies-not-met" });
  vector("trailing-newline-optional", "A log without its final newline.", [S.file], { did: u.did, options: { didLog: u.log.trimEnd() } },
    { didDocument: u.state(3) });

  const r = new DidLog().genesis({ nextKeyHashes: [kh("k2")] })
    .update({ updateKeys: [mk("k2")], nextKeyHashes: [kh("k3")] }, { signers: ["k2"] });
  vector("pre-rotation", "Pre-rotation works as in VH-Log.", ["#authorized-keys"], { did: r.did, options: { didLog: r.log } },
    { didDocument: r.state(2) });
});

group("deactivation", () => {
  const b = new DidLog().genesis().update().update({ deactivated: true });
  const opts = { didLog: b.log };
  vector("latest", "A deactivated DID: no document, deactivated true.", [S.deact], { did: b.did, options: opts },
    { didDocument: null, didDocumentMetadata: { deactivated: true, versionId: b.vid(3) } });
  vector("earlier-version", "An earlier version of a deactivated DID is returned, with deactivated true.", [S.deact],
    { did: b.did, options: { ...opts, versionNumber: 2 } }, { didDocument: b.state(2), didDocumentMetadata: { deactivated: true } });
  vector("deactivating-version", "Selecting the deactivating entry itself returns its document, with deactivated true.", [S.deact, PROFILE + "#5-resolution"],
    { did: b.did, options: { ...opts, versionNumber: 3 } }, { didDocument: b.state(3), didDocumentMetadata: { deactivated: true } });
  vector("deactivating-version-time", "A versionTime that selects the deactivating entry also returns its document.", [S.deact, PROFILE + "#5-resolution"],
    { did: b.did, options: { ...opts, versionTime: "2026-06-01T00:00:00Z" } }, { didDocument: b.state(3), didDocumentMetadata: { deactivated: true } });
  const after = new DidLog().genesis().update({ deactivated: true }).update();
  vector("entry-after-deactivation", "An entry after deactivation is invalid; the deactivated DID is still reported.", [S.deact],
    { did: after.did, options: { didLog: after.log } }, { didDocument: null, didDocumentMetadata: { deactivated: true }, warnings: ["invalid-entries"] });
});

group("witnesses", () => {
  const b = new DidLog().genesis({ witness: witnessConfig(2, "wA", "wB", "wC") }).update();
  const file = witnessFile([b.vid(2), "wA", "wC"]);
  vector("witnessed", "Witnessed log with didWitness; threshold is a string in the metadata.", [S.witnesses, S.meta],
    { did: b.did, options: { didLog: b.log, didWitness: file } },
    { didDocument: b.state(2), didDocumentMetadata: { witness: { threshold: 2, witnesses: witnessConfig(2, "wA", "wB", "wC").witnesses } } });
  vector("missing-witness-file", "Witnesses are required but no didWitness is given.", [S.witnesses], { did: b.did, options: { didLog: b.log } },
    { error: "invalidDid", vhLogError: "witness-threshold-not-met" });
  vector("below-threshold", "Only one of two required witness approvals.", [S.witnesses],
    { did: b.did, options: { didLog: b.log, didWitness: witnessFile([b.vid(2), "wA"]) } },
    { error: "invalidDid", vhLogError: "witness-threshold-not-met" });
  vector("malformed-witness-record", "A didWitness array whose record is malformed fails as in VH-Log.", [S.witnesses],
    { did: b.did, options: { didLog: b.log, didWitness: [{ versionId: b.vid(2) }] } }, { error: "invalidDid", vhLogError: "invalid-witness-file" });
  const plain = new DidLog().genesis().update();
  vector("unused-witness-file", "didWitness given for a log without witnesses is ignored.", [S.options],
    { did: plain.did, options: { didLog: plain.log, didWitness: [] } }, { didDocument: plain.state(2) });
});

group("log", () => {
  const ok = new DidLog().genesis();
  const asVhLog = new DidLog().genesis({ logVersion: "vh-log:1.0", scid: SCID_PLACEHOLDER, updateKeys: [mk("k1")] }, { raw: true });
  vector("vh-log-version-parameter", "A plain VH-Log log (logVersion, no method) is not a did:vh log.", [S.params],
    { did: asVhLog.did, options: { didLog: asVhLog.log } }, { error: "invalidDid", vhLogError: "invalid-parameter" });
  const noMethod = new DidLog().genesis({ scid: SCID_PLACEHOLDER, updateKeys: [mk("k1")] }, { raw: true });
  vector("method-missing", "The first entry has no method parameter.", [S.params], { did: noMethod.did, options: { didLog: noMethod.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });
  const webvh = new DidLog().genesis({ method: "did:webvh:1.0" });
  vector("method-webvh", "A did:webvh method value is malformed for did:vh.", [S.file, S.params], { did: webvh.did, options: { didLog: webvh.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });
  const leadingZero = new DidLog().genesis({ method: "did:vh:01.0" });
  vector("method-leading-zero", "A method version with a leading zero is malformed.", [S.params], { did: leadingZero.did, options: { didLog: leadingZero.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });
  const notString = new DidLog().genesis({ method: 1 });
  vector("method-not-string", "A method that is not a string is malformed.", [S.params], { did: notString.did, options: { didLog: notString.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });
  const future = new DidLog().genesis({ method: "did:vh:1.1" });
  vector("method-unsupported", "A well-formed method this resolver does not support.", [S.params, S.results], { did: future.did, options: { didLog: future.log } },
    { error: "featureNotSupported", vhLogError: "unsupported-log-version" });
  const upgrade = new DidLog().genesis().update().update({ method: "did:vh:2.0" });
  vector("method-unsupported-later", "An unsupported method in entry 3: the latest version is not returned.", [S.results],
    { did: upgrade.did, options: { didLog: upgrade.log } }, { error: "featureNotSupported", vhLogError: "unsupported-log-version" });
  vector("method-unsupported-earlier-version", "An earlier version before the unsupported entry is still returned.", [S.results],
    { did: upgrade.did, options: { didLog: upgrade.log, versionNumber: 2 } }, { didDocument: upgrade.state(2), warnings: ["invalid-entries"] });
  vector("method-unsupported-selected", "Selecting the unsupported entry.", [S.results],
    { did: upgrade.did, options: { didLog: upgrade.log, versionNumber: 3 } }, { error: "featureNotSupported", vhLogError: "unsupported-log-version" });
  const malformedLater = new DidLog().genesis().update({ method: "did:vh:x" });
  vector("method-malformed-later", "A malformed method in entry 2 invalidates it; entry 1 is returned.", [S.params, S.results],
    { did: malformedLater.did, options: { didLog: malformedLater.log } }, { didDocument: malformedLater.state(1), warnings: ["invalid-entries"] });
  const both = new DidLog().genesis({ logVersion: "vh-log:1.0" });
  vector("method-and-log-version", "method plus a logVersion parameter.", [S.params], { did: both.did, options: { didLog: both.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });
  const portable = new DidLog().genesis({ portable: true });
  vector("portable", "The did:webvh portable parameter is not allowed.", [S.file, S.params], { did: portable.did, options: { didLog: portable.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });
  const portableLater = new DidLog().genesis().update({ portable: false });
  vector("portable-later", "portable in a later entry invalidates that entry.", [S.params], { did: portableLater.did, options: { didLog: portableLater.log } },
    { didDocument: portableLater.state(1), warnings: ["invalid-entries"] });
  const custom = new DidLog().genesis({ "example:custom": 1 });
  vector("unknown-parameter", "did:vh's parameter set is closed.", [S.params], { did: custom.did, options: { didLog: custom.log } },
    { error: "invalidDid", vhLogError: "invalid-parameter" });

  const webvhId = new DidLog().genesis({}, { state: doc(`did:webvh:${SCID_PLACEHOLDER}:example.com`) });
  vector("state-id-webvh", "state.id is a did:webvh DID.", [S.file, S.algo], { did: webvhId.did, options: { didLog: webvhId.log } },
    { error: "invalidDid", vhLogError: "invalid-state" });
  const srcId = new DidLog().genesis({}, { state: doc(`did:vh:${SCID_PLACEHOLDER}?src=https://example.com`) });
  vector("state-id-with-query", "state.id is a DID URL, not the DID.", [S.file], { did: srcId.did, options: { didLog: srcId.log } },
    { error: "invalidDid", vhLogError: "invalid-state" });
  const noId = new DidLog().genesis({}, { state: { "@context": ["https://www.w3.org/ns/did/v1"] } });
  vector("state-id-missing", "state has no id.", [S.algo], { did: noId.did, options: { didLog: noId.log } },
    { error: "invalidDid", vhLogError: "invalid-state" });
  const changed = new DidLog().genesis().update({}, { state: doc("did:vh:QmOtherOtherOtherOtherOtherOtherOtherOtherOther") });
  vector("state-id-changed", "A later entry changes state.id; earlier entries stay valid.", [S.algo, "#update-rotate"],
    { did: changed.did, options: { didLog: changed.log } }, { didDocument: changed.state(1), warnings: ["invalid-entries"] });
  vector("state-id-changed-selected", "Selecting the entry that changed state.id fails.", [S.algo],
    { did: changed.did, options: { didLog: changed.log, versionNumber: 2 } }, { error: "invalidDid", vhLogError: "invalid-state" });

  const other = new DidLog().genesis({}, { time: t(2) });
  vector("did-mismatch", "A valid did:vh log for a different DID.", [S.algo], { did: other.did, options: { didLog: ok.log } },
    { error: "invalidDid", vhLogError: "invalid-state" });

  const badSig = new DidLog().genesis().update().update().tamper((e) => {
    (e.proof as Json[])[0].proofValue = createProof({ x: 1 }, KEYS.k1).proofValue;
  });
  vector("invalid-later-entry", "Entry 3 has a bad proof; entry 2 is returned with a warning.", [S.read],
    { did: badSig.did, options: { didLog: badSig.log } }, { didDocument: badSig.state(2), warnings: ["invalid-entries"] });
  vector("invalid-later-entry-selected", "Selecting the invalid entry fails with invalidDid.", [S.meta],
    { did: badSig.did, options: { didLog: badSig.log, versionNumber: 3 } }, { error: "invalidDid", vhLogError: "invalid-proof" });
  vector("empty-log", "An empty didLog.", [S.meta], { did: ok.did, options: { didLog: "" } }, { error: "invalidDid", vhLogError: "invalid-log" });
  vector("not-json", "A didLog that is not JSON Lines.", [S.meta], { did: ok.did, options: { didLog: "not json\n" } },
    { error: "invalidDid", vhLogError: "invalid-log" });
});

group("did", () => {
  const b = new DidLog().genesis();
  const opts = { didLog: b.log };
  const bad = (name: string, value: string, description: string) =>
    vector(name, description, [S.id, S.algo], { did: value, options: opts }, { error: "invalidDid" });
  bad("webvh", `did:webvh:${b.scid}:example.com`, "A did:webvh DID.");
  bad("uppercase-method", `did:VH:${b.scid}`, "The method name must be lowercase.");
  bad("short-scid", `did:vh:${b.scid.slice(0, 45)}`, "A 45-character SCID.");
  bad("long-scid", `did:vh:${b.scid}1`, "A 47-character SCID.");
  bad("non-base58", `did:vh:${b.scid.slice(0, 45)}0`, "0 is not in the base58btc alphabet.");
  bad("did-url", `did:vh:${b.scid}?versionNumber=1`, "resolve takes a DID, not a DID URL.");
  bad("fragment", `did:vh:${b.scid}#key-1`, "resolve takes a DID, not a DID URL.");
  bad("location", `did:vh:${b.scid}:example.com`, "did:vh has no location component.");
  vector("invalid-did-before-options", "An invalid DID is reported before invalid options.", [S.algo],
    { did: "did:vh:x", options: {} }, { error: "invalidDid" });
});

group("options", () => {
  const b = new DidLog().genesis();
  const base = { did: b.did };
  const invalid = (name: string, options: Json, description: string, remote?: boolean) =>
    vector(name, description, [S.options], { ...base, options, ...(remote === undefined ? {} : { remote }) }, { error: "invalidOptions" });
  invalid("no-log", {}, "Neither didLog nor srcLog.");
  invalid("log-and-src-log", { didLog: b.log, srcLog: "https://example.com/did.jsonl" }, "Both didLog and srcLog.");
  invalid("witness-and-src-witness", { didLog: b.log, didWitness: [], srcWitness: "https://example.com/did-witness.json" }, "Both didWitness and srcWitness.");
  invalid("log-not-string", { didLog: [b.log] }, "didLog must be a string.");
  invalid("witness-not-array", { didLog: b.log, didWitness: {} }, "didWitness must be an array.");
  invalid("two-selectors", { didLog: b.log, versionNumber: 1, versionId: b.vid(1) }, "More than one version selector.");
  invalid("version-number-zero", { didLog: b.log, versionNumber: 0 }, "versionNumber must be positive.");
  invalid("version-number-string", { didLog: b.log, versionNumber: "1" }, "versionNumber must be a number.");
  invalid("version-number-fraction", { didLog: b.log, versionNumber: 1.5 }, "versionNumber must be an integer.");
  invalid("version-time-fraction", { didLog: b.log, versionTime: "2026-01-01T00:00:00.5Z" }, "versionTime must have whole seconds.");
  invalid("version-id-number", { didLog: b.log, versionId: 1 }, "versionId must be a string.");
  invalid("min-copies-zero", { didLog: b.log, minCopies: 0 }, "minCopies must be positive.");
  invalid("check-watchers-boolean", { didLog: b.log, checkWatchers: true }, 'checkWatchers must be a non-negative integer or "all".');
  invalid("check-watchers-negative", { didLog: b.log, checkWatchers: -1 }, "checkWatchers must not be negative.");
  invalid("check-watchers-other-string", { didLog: b.log, checkWatchers: "some" }, 'The only string checkWatchers value is "all".');
  invalid("extra-watchers-http", { didLog: b.log, extraWatchers: ["http://watcher.example"] }, "extraWatchers must be https URLs.");
  invalid("extra-watchers-string", { didLog: b.log, extraWatchers: "https://watcher.example" }, "extraWatchers must be an array.");
  invalid("include-did-log-string", { didLog: b.log, includeDidLog: "yes" }, "includeDidLog must be a boolean.");
  invalid("src-log-invalid", { srcLog: "http://example.com/did.jsonl" }, "srcLog: http is only for loopback hosts.");
  invalid("src-log-fragment", { srcLog: "https://example.com/did.jsonl#x" }, "srcLog must not have a fragment.");
  invalid("src-witness-invalid", { didLog: b.log, srcWitness: "https://192.0.2.1/did-witness.json" }, "srcWitness: https needs a domain name.");
  invalid("src-log-file-remote", { srcLog: "file:///var/lib/dids/did.jsonl" }, "A resolver serving other systems refuses local file references.", true);
  invalid("src-log-loopback-remote", { srcLog: "http://localhost:8000/did.jsonl" }, "A resolver serving other systems refuses loopback references.", true);
  invalid("src-witness-file-remote", { didLog: b.log, srcWitness: "file:///var/lib/dids/did-witness.json" }, "The check applies to srcWitness too, even when it is not needed.", true);

  const unsupported = (name: string, options: Json, description: string) =>
    vector(name, description, [S.options, PROFILE + "#5-resolution"], { ...base, options }, { error: "featureNotSupported" });
  unsupported("src-log-web", { srcLog: "https://example.com/dids/issuer/did.jsonl" }, "This resolver does not retrieve from web locations.");
  unsupported("src-log-file-local", { srcLog: "file:///var/lib/dids/did.jsonl" }, "This resolver does not read local files.");
  unsupported("src-log-other-scheme", { srcLog: "ipfs://bafkreiexample" }, "This resolver does not support other schemes.");
  unsupported("check-watchers", { didLog: b.log, checkWatchers: 1 }, "This resolver does not contact watchers.");
  unsupported("check-watchers-all", { didLog: b.log, checkWatchers: "all" }, "This resolver does not contact watchers.");
  unsupported("extra-watchers", { didLog: b.log, extraWatchers: ["https://watcher.example"] }, "This resolver does not contact watchers.");
  vector("watchers-zero", "checkWatchers 0 and an empty extraWatchers need no watchers.", [S.options],
    { ...base, options: { didLog: b.log, checkWatchers: 0, extraWatchers: [] } }, { didDocument: b.state(1) });
  vector("src-witness-unneeded", "srcWitness is not an error when the log needs no witnesses.", [S.refs],
    { ...base, options: { didLog: b.log, srcWitness: "https://example.com/did-witness.json" } }, { didDocument: b.state(1) });
  const w = new DidLog().genesis({ witness: witnessConfig(1, "wA") });
  vector("src-witness-needed", "This resolver does not retrieve a srcWitness the log needs.", [S.refs, PROFILE + "#5-resolution"],
    { did: w.did, options: { didLog: w.log, srcWitness: "https://example.com/did-witness.json" } }, { error: "featureNotSupported" });

  const invalidWitness = new DidLog().genesis().update({ witness: witnessConfig(1, "wA") }).tamper((e) => {
    (e.proof as Json[])[0].proofValue = createProof({ x: 1 }, KEYS.k1).proofValue;
  });
  vector("src-witness-invalid-entry", "A witness list set only in an invalid entry is never active, so srcWitness is ignored.", [S.refs, PROFILE + "#5-resolution"],
    { did: invalidWitness.did, options: { didLog: invalidWitness.log, srcWitness: "https://example.com/did-witness.json" } },
    { didDocument: invalidWitness.state(1), warnings: ["invalid-entries"] });
  vector("include-did-log-invalid-witness-entry", "No didWitness is returned when only an invalid entry sets a witness list.", [S.meta],
    { did: invalidWitness.did, options: { didLog: invalidWitness.log, didWitness: [], includeDidLog: true } },
    { didDocument: invalidWitness.state(1), warnings: ["invalid-entries"] });
  const laterWitness = new DidLog().genesis().update({ witness: witnessConfig(1, "wA") });
  vector("src-witness-later-entry", "A valid later entry that turns witnessing on makes the log need witnessing.", [S.refs, PROFILE + "#5-resolution"],
    { did: laterWitness.did, options: { didLog: laterWitness.log, srcWitness: "https://example.com/did-witness.json" } }, { error: "featureNotSupported" });

  const u = new DidLog().genesis().update().update().tamper((e) => {
    (e.proof as Json[])[0].proofValue = createProof({ x: 1 }, KEYS.k1).proofValue;
  });
  vector("include-did-log", "includeDidLog returns the valid entries, not shortened to the selected version.", [S.meta],
    { did: u.did, options: { didLog: u.log, includeDidLog: true, versionNumber: 1 } }, { didDocument: u.state(1) });
  vector("include-did-log-false", "includeDidLog false returns nothing extra.", [S.meta],
    { did: u.did, options: { didLog: u.log, includeDidLog: false } }, { didDocument: u.state(2), warnings: ["invalid-entries"] });
  const wf = witnessFile([w.vid(1), "wA"]);
  vector("include-did-log-witness", "includeDidLog also returns the witness proofs file when witnesses are required.", [S.meta],
    { did: w.did, options: { didLog: w.log, didWitness: wf, includeDidLog: true } }, { didDocument: w.state(1) });
  vector("include-did-log-on-error", "Nothing is returned when resolution fails.", [S.meta],
    { did: u.did, options: { didLog: u.log, includeDidLog: true, versionNumber: 3 } }, { error: "invalidDid", vhLogError: "invalid-proof" });
});

// ---------------------------------------------------------------- srcLog / srcWitness references

function refCases() {
  const cases: [string, unknown][] = [
    // web locations
    ["web", "https://example.com/dids/issuer/did.jsonl"],
    ["web-port", "https://example.com:3000/dids/did.jsonl"],
    ["web-query", "https://storage.example.com/did.jsonl?X-Sig=abc&exp=1"],
    ["web-watcher-operation", "https://watcher.example.org/log?scid=QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ"],
    ["web-root-path", "https://example.com/"],
    ["web-empty-segment", "https://example.com/a//did.jsonl"],
    ["web-trailing-slash", "https://example.com/dids/"],
    ["web-space-segment", "https://example.com/%20/did.jsonl"],
    ["web-uppercase", "HTTPS://Example.COM/did.jsonl"],
    ["web-punycode", "https://xn--bcher-kva.example/did.jsonl"],
    ["web-trailing-dot-host", "https://example.com./did.jsonl"],
    ["web-no-path", "https://example.com"],
    ["web-fragment", "https://example.com/did.jsonl#x"],
    ["web-dot-dot", "https://example.com/a/../did.jsonl"],
    ["web-encoded-dot-dot", "https://example.com/a/%2e%2e/did.jsonl"],
    ["web-encoded-slash", "https://example.com/a%2Fb/did.jsonl"],
    ["web-encoded-backslash", "https://example.com/a%5Cb/did.jsonl"],
    ["web-encoded-nul", "https://example.com/a%00/did.jsonl"],
    ["web-bad-percent", "https://example.com/a%zz/did.jsonl"],
    ["web-bad-utf8", "https://example.com/a%FF/did.jsonl"],
    ["web-dot-dot-in-query", "https://example.com/did.jsonl?p=../x"],
    ["web-userinfo", "https://user@example.com/did.jsonl"],
    ["web-ipv4", "https://192.0.2.1/did.jsonl"],
    ["web-ipv6", "https://[2001:db8::1]/did.jsonl"],
    ["web-numeric-tld", "https://example.123/did.jsonl"],
    ["web-empty-host", "https:///did.jsonl"],
    ["web-bad-port", "https://example.com:99999/did.jsonl"],
    ["web-underscore-host", "https://ex_ample.com/did.jsonl"],
    ["web-no-authority", "https:example.com/did.jsonl"],
    ["web-unicode-host", "https://bücher.example/did.jsonl"],
    ["web-space", "https://example.com/a b/did.jsonl"],
    // loopback
    ["localhost", "http://localhost:8000/dids/did.jsonl"],
    ["loopback-ipv4", "http://127.0.0.1/did.jsonl"],
    ["loopback-ipv6", "http://[::1]:8000/did.jsonl"],
    ["loopback-no-path", "http://localhost:8000"],
    ["http-public", "http://example.com/did.jsonl"],
    ["http-private", "http://10.0.0.1/did.jsonl"],
    ["http-leading-zero", "http://127.0.0.01/did.jsonl"],
    // local files
    ["file-empty-host", "file:///var/lib/wallet/dids/QmfGEU/did.jsonl"],
    ["file-localhost", "file://LOCALHOST/home/alice/did-witness.json"],
    ["file-no-authority", "file:/var/lib/dids/did.jsonl"],
    ["file-dot-dot", "file:///var/lib/../etc/did.jsonl"],
    ["file-encoded-dot-dot", "file:///var/%2E%2E/did.jsonl"],
    ["file-other-host", "file://server/share/did.jsonl"],
    ["file-relative", "file:did.jsonl"],
    ["file-query", "file:///var/lib/did.jsonl?x"],
    // other schemes
    ["ipns", "ipns://k51qzi5uqu5d/dids/issuer/did.jsonl"],
    ["ipfs-content-hash", "ipfs://bafkreiexample"],
    ["urn", "urn:example:did-log"],
    ["other-fragment", "ipfs://bafkreiexample#x"],
    ["other-empty", "ipfs:"],
    // not URLs
    ["relative", "/dids/did.jsonl"],
    ["empty", ""],
    ["number", 42],
  ];
  return cases.map(([name, ref]) => {
    try {
      return { name, ref, expect: { valid: true, kind: checkRef(ref) } };
    } catch (e) {
      if (!(e instanceof DidVhError)) throw e;
      return { name, ref, expect: { valid: false, error: "invalidOptions" } };
    }
  });
}

// ---------------------------------------------------------------- the src DID URL parameter

function srcCases() {
  const cases: [string, unknown][] = [
    ["root", "https://example.com"],
    ["root-slash", "https://example.com/"],
    ["well-known", "https://example.com/.well-known"],
    ["path", "https://example.com/dids/issuer"],
    ["path-slash", "https://example.com/dids/issuer/"],
    ["port", "https://example.com:3000/dids/issuer"],
    ["scid-path", "https://example.com/users/QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ"],
    ["uppercase-scheme", "HTTPS://example.com/dids"],
    ["percent-encoded-segment", "https://example.com/a%20b"],
    ["ipns", "ipns://k51qzi5uqu5d/dids/issuer"],
    ["ipfs-slash", "ipfs://bafybeigdyrzt/"],
    ["double-trailing-slash", "https://example.com/dids//"],
    ["empty-segment", "https://example.com/a//b"],
    ["dot-dot", "https://example.com/a/../b"],
    ["encoded-slash", "https://example.com/a%2Fb"],
    ["leading-space", "https://example.com/%20a"],
    ["trailing-nbsp", "https://example.com/a%C2%A0"],
    ["query", "https://example.com/dids?x=1"],
    ["fragment", "https://example.com/dids#x"],
    ["http-loopback", "http://localhost:8000/dids"],
    ["http-public", "http://example.com/dids"],
    ["file", "file:///var/lib/dids"],
    ["ipv4-host", "https://192.0.2.1/dids"],
    ["userinfo", "https://user@example.com/dids"],
    ["urn", "urn:example:dids"],
    ["other-empty-authority", "ipfs:///x"],
    ["relative", "/dids"],
  ];
  return cases.map(([name, src]) => {
    try {
      return { name, src, expect: { valid: true, ...srcReferences(src) } };
    } catch (e) {
      if (!(e instanceof DidVhError)) throw e;
      return { name, src, expect: { valid: false, error: "invalidDidUrl" } };
    }
  });
}

// ---------------------------------------------------------------- DID URLs

function didUrlCases() {
  const scid = "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ";
  const d = `did:vh:${scid}`;
  const cases: [string, unknown][] = [
    ["plain", d],
    ["fragment", `${d}#key-1`],
    ["empty-fragment", `${d}#`],
    ["src", `${d}?src=https://example.com/dids/issuer`],
    ["src-encoded", `${d}?src=https%3A%2F%2Fexample.com%2Fdids%2Fissuer`],
    ["src-encoded-segment", `${d}?src=https://example.com/a%2520b`],
    ["version-number", `${d}?versionNumber=3`],
    ["version-id", `${d}?versionId=1-QmRRaLXwc6BjBuBPosSupJwEQ8w9f3znP7yfbpGfwcnLr6`],
    ["version-time", `${d}?versionTime=2026-01-01T00:00:00Z`],
    ["version-time-encoded", `${d}?versionTime=2026-01-01T00%3A00%3A00Z`],
    ["src-and-version", `${d}?src=https://example.com&versionNumber=2#key-1`],
    ["unknown-parameter", `${d}?service=files&versionNumber=2`],
    ["two-selectors-passed-on", `${d}?versionNumber=2&versionId=x`],
    ["src-twice", `${d}?src=https://a.example&src=https://b.example`],
    ["version-number-twice", `${d}?versionNumber=1&versionNumber=2`],
    ["version-number-zero", `${d}?versionNumber=0`],
    ["version-number-leading-zero", `${d}?versionNumber=01`],
    ["version-number-text", `${d}?versionNumber=two`],
    ["did-log", `${d}?didLog=x`],
    ["did-witness", `${d}?didWitness=x`],
    ["src-log", `${d}?srcLog=https://example.com/did.jsonl`],
    ["src-witness", `${d}?srcWitness=https://example.com/did-witness.json`],
    ["check-watchers", `${d}?checkWatchers=1`],
    ["include-did-log", `${d}?includeDidLog=true`],
    ["src-ipns", `${d}?src=ipns://k51qzi5uqu5d/dids`],
    ["no-value", `${d}?versionNumber`],
    ["bad-percent", `${d}?versionId=%zz`],
    ["src-file", `${d}?src=file:///var/lib/dids`],
    ["src-loopback", `${d}?src=http://localhost:8000/dids`],
    ["src-invalid", `${d}?src=https://example.com/a/../b`],
    ["src-http-public", `${d}?src=http://example.com`],
    ["plus-not-space", `${d}?versionId=a+b`],
    ["raw-non-ascii", `${d}?versionId=1-é😀`],
    ["raw-and-encoded-non-ascii", `${d}?versionId=😀%F0%9F%98%80`],
    ["not-did-vh", `did:webvh:${scid}:example.com`],
    ["bad-scid", "did:vh:Qm1?versionNumber=1"],
    ["path", `${d}/whois`],
    ["not-string", 7],
  ];
  return cases.map(([name, didUrl]) => {
    try {
      return { name, didUrl, expect: { valid: true, ...parseDidUrl(didUrl) } };
    } catch (e) {
      if (!(e instanceof DidVhError)) throw e;
      return { name, didUrl, expect: { valid: false, error: e.code } };
    }
  });
}

// ---------------------------------------------------------------- generation

function generation() {
  const s = (n: string) => KEYS[n];
  const D = `did:vh:${SCID_PLACEHOLDER}`;
  const scenarios = [
    {
      name: "create-update-deactivate",
      description: "Create a did:vh DID, add a service, then deactivate it.",
      steps: [
        { op: "didvh-create", input: { document: doc(D), parameters: { updateKeys: [mk("k1")] }, versionTime: t(1), signers: [s("k1")] } },
        { op: "didvh-update", input: { document: doc(D, { service: [{ id: `${D}#files`, type: "relativeRef", serviceEndpoint: "https://example.com/files/" }] }), parameters: {}, versionTime: t(2), signers: [s("k1")] } },
        { op: "didvh-update", input: { document: doc(D), parameters: { deactivated: true }, versionTime: t(3), signers: [s("k1")] } },
      ],
    },
    {
      name: "pre-rotation-witnesses-watchers",
      description: "Pre-rotation, witnesses, watchers and ttl.",
      steps: [
        { op: "didvh-create", input: { document: doc(D), parameters: { updateKeys: [mk("k1")], nextKeyHashes: [kh("k2")], witness: witnessConfig(1, "wA", "wB"), watchers: ["https://watcher.example"], ttl: 60 }, versionTime: t(1), signers: [s("k1")] } },
        { op: "didvh-update", input: { document: doc(D, { alsoKnownAs: ["https://example.com/alice"] }), parameters: { updateKeys: [mk("k2")], nextKeyHashes: [kh("k3")] }, versionTime: t(2), signers: [s("k2")] } },
      ],
      witness: [{ step: 2, seeds: [s("wB")] }],
    },
    {
      name: "unicode-document",
      description: "A DID document exercising JCS escaping and numbers.",
      steps: [
        { op: "didvh-create", input: { document: doc(D, { "ö": "ü", "😀": [0.1, 1e21, -0], note: "line\nbreak" }), parameters: { updateKeys: [mk("k1"), mk("k2")] }, versionTime: t(1), signers: [s("k1"), s("k2")] } },
      ],
    },
  ];
  return {
    description: "did:vh generation scenarios. Run the steps in order, threading `log` from each output into the next didvh-update; `{SCID}` in a didvh-update document is replaced by the harness with the SCID from didvh-create. Compare each new line, parsed, to `expect.line`. Then resolve with didvh-resolve.",
    scenarios: scenarios.map((sc) => {
      let log = "";
      let scid = "";
      let didValue = "";
      const steps = sc.steps.map((step) => {
        let result: { log: string; versionId: string; scid?: string; did?: string };
        if (step.op === "didvh-create") {
          result = createDid(step.input as never);
          scid = result.scid!;
          didValue = result.did!;
        } else {
          const input = JSON.parse(JSON.stringify(step.input).replaceAll(SCID_PLACEHOLDER, scid));
          result = updateDid({ ...input, log });
        }
        log = result.log;
        const line = JSON.parse(log.trimEnd().split("\n").at(-1)!);
        return { ...step, expect: { versionId: result.versionId, ...(result.did ? { did: result.did, scid: result.scid } : {}), line } };
      });
      const versionIds = steps.map((st) => st.expect.versionId);
      const witnessFileOut = (sc.witness ?? []).map((w) => ({
        versionId: versionIds[w.step - 1],
        proof: w.seeds.map((seedHex) => witnessProof(versionIds[w.step - 1], seedHex)),
      }));
      const options = { didLog: log, ...(sc.witness ? { didWitness: witnessFileOut } : {}) };
      const resolved = resolveDid(didValue, options, { now: NOW });
      if ("error" in resolved.didResolutionMetadata) throw new Error(`scenario ${sc.name} does not resolve: ${JSON.stringify(resolved)}`);
      return {
        name: sc.name,
        description: sc.description,
        steps,
        ...(sc.witness ? { witness: sc.witness, witnessFile: witnessFileOut } : {}),
        log,
        resolve: { now: NOW, did: didValue, didDocument: resolved.didDocument, didDocumentMetadata: resolved.didDocumentMetadata },
      };
    }),
  };
}

// ---------------------------------------------------------------- write

function write(path: string, value: unknown) {
  const file = join(OUT, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
}

let total = 0;
for (const [name, cases] of Object.entries(groups)) {
  write(`resolution/${name}.json`, { description: `did:vh resolution vectors: ${name}. Call didvh-resolve with input; compare didResolutionMetadata.error and problemDetails.vhLog.code, or the document, metadata and sorted warning codes.`, cases });
  total += cases.length;
}
const refs = refCases();
write("ref.json", { description: "did:vh srcLog and srcWitness references (didvh-ref). A valid reference gives its kind (web, loopback, file or other); an invalid one gives invalidOptions.", spec: [SPEC + S.refs, PROFILE + "#31-srclog-and-srcwitness"], cases: refs });
const src = srcCases();
write("src.json", { description: "The did:vh src DID URL parameter (didvh-src): a valid value gives the srcLog and srcWitness references derived from it; an invalid one gives invalidDidUrl.", spec: [SPEC + S.src, PROFILE + "#32-the-src-did-url-parameter"], cases: src });
const urls = didUrlCases();
write("did-url.json", { description: "did:vh DID URLs as parsed by a dereferencer (didvh-did-url).", spec: [SPEC + "#reading-didvh-did-urls", PROFILE + "#4-did-urls"], cases: urls });
write("generation.json", generation());
console.log(`wrote ${total} did:vh resolution vectors, ${refs.length} reference cases, ${src.length} src cases, ${urls.length} DID URL cases`);
