// Generates the shared test vectors in ../vectors from the TypeScript reference
// implementation. Run: node tools/generate-vectors.ts
//
// Vectors are consensus vectors: produced by one implementation and checked by
// all of them. Every invalid-log vector is built so that exactly one check
// (profile §4) fails.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  base58btcEncode,
  canonicalize,
  computeEntryHash,
  computeScid,
  createLog,
  createProof,
  hashB58,
  keyHash,
  LOG_VERSION,
  resolve,
  SCID_PLACEHOLDER,
  sealEntry,
  sealGenesis,
  serializeEntry,
  signerFromSeed,
  updateLog,
  witnessProof,
  type LogEntry,
} from "../implementations/typescript/src/index.ts";
import type { SealOptions } from "../implementations/typescript/src/log.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "vectors");
const SPEC = "https://github.com/swcurran/VH-Log/blob/f2f9fda/spec/specification.md";

// ---------------------------------------------------------------- fixtures

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

const witnessConfig = (threshold: number, ...names: string[]) => ({
  threshold,
  witnesses: names.map((n) => ({ id: did(n) })),
});

type Json = Record<string, unknown>;

/** Builds a log line by line; entries are sealed without validation. */
class LogBuilder {
  entries: Json[] = [];
  scid = "";

  genesis(
    parameters: Json = {},
    { state = { id: `example:${SCID_PLACEHOLDER}` }, signers = ["k1"], time = t(1), seal = {} as SealOptions, raw = false } = {},
  ): this {
    const params = raw ? parameters : { logVersion: LOG_VERSION, scid: SCID_PLACEHOLDER, updateKeys: [mk("k1")], ...parameters };
    const { entry, scid } = sealGenesis(
      { versionId: SCID_PLACEHOLDER, versionTime: time, parameters: params, state },
      signers.map((s) => KEYS[s]),
      seal,
    );
    this.scid = scid;
    this.entries.push(entry as unknown as Json);
    return this;
  }

  update(
    parameters: Json = {},
    { state, signers = ["k1"], time, seal = {} as SealOptions, extra = {} as Json } = {} as {
      state?: unknown; signers?: string[]; time?: string; seal?: SealOptions; extra?: Json;
    },
  ): this {
    const n = this.entries.length + 1;
    const prev = this.entries.at(-1)!.versionId as string;
    const entry = sealEntry(
      {
        versionId: prev,
        versionTime: time ?? t(n),
        parameters,
        state: state ?? { id: `example:${this.scid}`, version: n },
        ...extra,
      },
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

  vid(n: number): string {
    return this.entries[n - 1].versionId as string;
  }

  get log(): string {
    return this.entries.map(serializeEntry).join("");
  }

  fork(): LogBuilder {
    const b = new LogBuilder();
    b.entries = structuredClone(this.entries);
    b.scid = this.scid;
    return b;
  }

  truncate(n: number): LogBuilder {
    const b = this.fork();
    b.entries.length = n;
    return b;
  }
}

const witnessFile = (...records: [string, ...string[]][]) =>
  records.map(([versionId, ...witnesses]) => ({ versionId, proof: witnesses.map((w) => witnessProof(versionId, KEYS[w])) }));

const sha512Multihash = (data: string) =>
  base58btcEncode(Uint8Array.from([0x13, 0x40, ...createHash("sha512").update(data).digest()]));

/**
 * A genesis entry plus a hand-written second line whose `state` is `stateText`
 * verbatim, so number and key spellings survive; the hash and proof use the parsed value.
 */
function rawSecondLine(stateText: string): string {
  const b = new LogBuilder().genesis();
  const prev = b.vid(1);
  const doc = { versionId: prev, versionTime: t(2), parameters: {}, state: JSON.parse(stateText) };
  const versionId = `2-${computeEntryHash(doc, prev)}`;
  const proof = [createProof({ ...doc, versionId }, KEYS.k1, { created: t(2) })];
  return b.log + `{"versionId":"${versionId}","versionTime":"${t(2)}","parameters":{},"state":${stateText},"proof":${JSON.stringify(proof)}}\n`;
}

// ---------------------------------------------------------------- resolution cases

interface Expect {
  valid: boolean;
  error?: { code?: string; oneOf?: string[]; version?: number | null };
  state?: unknown;
  firstInvalidVersion?: number | null;
  metadata?: Json;
  warnings?: string[];
}

interface Case {
  name: string;
  description: string;
  spec: string[];
  input: Json;
  expect: Expect;
}

const groups: Record<string, Case[]> = {};
let currentGroup: Case[] = [];
function group(name: string, fn: () => void) {
  currentGroup = groups[name] = [];
  fn();
}

/**
 * Adds a case. `expect` is checked against the reference resolver here, so a
 * vector can never disagree with the implementation that generated it; fields
 * left out of `expect` are filled from the reference result (state, warnings).
 */
function vector(name: string, description: string, spec: string[], input: Json, expect: Expect) {
  const fullInput = { now: NOW, ...input };
  const result = resolve(fullInput as never) as Json;
  const fail = (why: string) => {
    throw new Error(`vector ${name}: ${why}\n${JSON.stringify(result, null, 2)}`);
  };
  if (result.valid !== expect.valid) fail(`expected valid=${expect.valid}`);
  const error = result.error as Json | null;
  if (expect.error) {
    if (!error) fail("expected an error");
    if (expect.error.code && error!.code !== expect.error.code) fail(`expected ${expect.error.code}, got ${error!.code}`);
    if (expect.error.oneOf && !expect.error.oneOf.includes(error!.code as string)) fail(`got ${error!.code}`);
    if (expect.error.version !== undefined && error!.version !== expect.error.version) {
      fail(`expected error version ${expect.error.version}, got ${error!.version}`);
    }
  } else if (error) {
    fail(`unexpected error ${error.code}`);
  }
  const final: Expect = { ...expect };
  if (result.valid) {
    const metadata = result.metadata as Json;
    if (expect.state !== undefined && canonicalize(expect.state) !== canonicalize(result.state)) fail("state differs");
    final.state = result.state;
    final.firstInvalidVersion = result.firstInvalidVersion as number | null;
    if (expect.firstInvalidVersion !== undefined && expect.firstInvalidVersion !== result.firstInvalidVersion) {
      fail(`expected firstInvalidVersion ${expect.firstInvalidVersion}`);
    }
    for (const [k, v] of Object.entries(expect.metadata ?? {})) {
      if (canonicalize(v) !== canonicalize(metadata[k])) fail(`metadata.${k} differs: ${JSON.stringify(metadata[k])}`);
    }
    const warnings = (metadata.warnings as Json[]).map((w) => w.code as string).sort();
    if (expect.warnings && canonicalize(expect.warnings.toSorted()) !== canonicalize(warnings)) {
      fail(`warnings differ: ${warnings}`);
    }
    final.warnings = warnings;
    final.metadata = {
      versionId: metadata.versionId,
      versionNumber: metadata.versionNumber,
      versionTime: metadata.versionTime,
      created: metadata.created,
      updated: metadata.updated,
      scid: metadata.scid,
      deactivated: metadata.deactivated,
      ttl: metadata.ttl,
      witness: metadata.witness,
      watchers: metadata.watchers,
      updateKeys: metadata.updateKeys,
      nextKeyHashes: metadata.nextKeyHashes,
      ...(metadata.copies ? { copies: metadata.copies } : {}),
    };
  }
  currentGroup.push({ name, description, spec: spec.map((a) => `${SPEC}${a}`), input: fullInput, expect: final });
}

const ok = (more: Partial<Expect> = {}): Expect => ({ valid: true, ...more });
const bad = (code: string, version: number | null, more: Partial<Expect> = {}): Expect => ({
  valid: false,
  error: { code, version },
  ...more,
});
/** Entries before `version` are valid; the log is reported partially valid. */
const partial = (code: string, version: number, more: Partial<Expect> = {}): Expect => ({
  valid: true,
  error: { code, version },
  firstInvalidVersion: version,
  warnings: ["invalid-entries"],
  ...more,
});

// ---- structure
group("structure", () => {
  vector("empty-log", "A log with no entries.", ["#read-resolve"], { log: "" }, bad("invalid-log", null));
  const base = new LogBuilder().genesis().update();
  vector("minimal-genesis", "A single, minimal genesis entry.", ["#create"], { log: new LogBuilder().genesis().log }, ok({
    metadata: { versionNumber: 1, deactivated: false, ttl: 3600, witness: null, watchers: [] },
  }));
  vector("two-entries", "Genesis and one update.", ["#update"], { log: base.log }, ok({ metadata: { versionNumber: 2 } }));
  vector("no-trailing-newline", "The last line has no terminating newline; it is still a valid JSON Lines file.",
    ["#the-vh-log-file"], { log: base.log.trimEnd() }, ok({ metadata: { versionNumber: 2 } }));
  vector("line-not-json", "Line 2 is not JSON.", ["#the-vh-log-file"],
    { log: new LogBuilder().genesis().log + "{not json\n" }, partial("invalid-log", 2));
  vector("line-is-array", "Line 1 is a JSON array, not an object.", ["#the-vh-log-file"], { log: "[]\n" }, bad("invalid-log", 1));
  vector("blank-line", "A blank line between entries.", ["#the-vh-log-file"],
    { log: base.entries.map(serializeEntry).join("\n") }, partial("invalid-log", 2));
  vector("extra-entry-property", "Entry 2 has an extra top-level property, included in its hash and proof.",
    ["#the-vh-log-file"], { log: new LogBuilder().genesis().update({}, { extra: { note: "x" } }).log }, partial("invalid-entry", 2));
  vector("missing-proof-property", "Entry 2 has no proof property.", ["#the-vh-log-file"],
    { log: base.fork().tamper((e) => delete e.proof).log }, partial("invalid-entry", 2));
  vector("state-not-object", "Entry 2's state is a JSON array.", ["#the-vh-log-file"],
    { log: new LogBuilder().genesis().update({}, { state: [1, 2] }).log }, partial("invalid-entry", 2));
  vector("parameters-not-object", "Entry 2's parameters is a JSON array.", ["#the-vh-log-file"],
    { log: new LogBuilder().genesis().update([] as unknown as Json).log }, partial("invalid-entry", 2));
  vector("jcs-numbers-in-state", "State with numbers whose JCS form differs from their source text (IEEE-754 doubles).",
    ["#generate-entry-hash"], { log: rawSecondLine('{"big":123456789012345678,"one":1.0,"exp":1E21,"small":0.000001,"neg":-0,"f":896365914996807.2}') },
    ok({ metadata: { versionNumber: 2 } }));
  vector("duplicate-key-last-wins", "Entry 2's state repeats a key; the last value is the one hashed, signed and returned.",
    ["#the-vh-log-file"], { log: rawSecondLine('{"a":1,"a":2}') }, ok({ state: { a: 2 } }));
  vector("number-overflow", "Entry 2 contains 1e400, which is not a finite double.", ["#the-vh-log-file"], {
    log: new LogBuilder().genesis().log +
      `{"versionId":"2-QmUnused","versionTime":"${t(2)}","parameters":{},"state":{"n":1e400},"proof":[]}\n`,
  }, partial("invalid-log", 2));
  vector("lone-surrogate", "Entry 2's state contains a lone surrogate escape; it is hashed and signed, but not I-JSON.",
    ["#the-vh-log-file"], { log: new LogBuilder().genesis().update({}, { state: { s: "x\ud800" } }).log }, partial("invalid-log", 2));
  vector("lone-surrogate-key", "Entry 2's state has a key containing a lone surrogate.",
    ["#the-vh-log-file"], { log: new LogBuilder().genesis().update({}, { state: { "\udc00": 1 } }).log }, partial("invalid-log", 2));
});

// ---- versionId
group("version-id", () => {
  const g = () => new LogBuilder().genesis();
  vector("wrong-version-number", "Entry 2 is numbered 3.", ["#read-resolve"],
    { log: g().update({}, { seal: { versionNumber: 3 } }).log }, partial("invalid-version-id", 2));
  vector("leading-zero-version-number", "Entry 2 is numbered 02.", ["#read-resolve"],
    { log: g().update({}, { seal: { versionNumber: "02" } }).log }, partial("invalid-version-id", 2));
  vector("genesis-version-zero", "The genesis entry is numbered 0.", ["#read-resolve"],
    { log: new LogBuilder().genesis({}, { seal: { versionNumber: 0 } }).log }, bad("invalid-version-id", 1));
  vector("double-dash", "Entry 2's versionId has two dashes.", ["#read-resolve"],
    { log: g().update({}, { seal: { versionNumber: "2-" } }).log }, partial("invalid-version-id", 2));
  vector("entry-hash-mismatch", "Entry 2's versionId carries a valid SHA-256 multihash of the wrong content; the proof signs that versionId.",
    ["#verify-the-entry-hash"], { log: g().update({}, { seal: { entryHash: hashB58("wrong") } }).log }, partial("entry-hash-mismatch", 2));
  vector("genesis-entry-hash-mismatch", "The genesis versionId carries the wrong hash.", ["#verify-the-entry-hash"],
    { log: new LogBuilder().genesis({}, { seal: { entryHash: hashB58("wrong") } }).log }, bad("entry-hash-mismatch", 1));
  vector("sha512-entry-hash", "Entry 2's entry hash is a SHA-512 multihash, not permitted by vh-log:1.0.", ["#vh-log-parameters"],
    { log: g().update({}, { seal: { entryHash: sha512Multihash("x") } }).log }, partial("invalid-hash-algorithm", 2));
  vector("entry-hash-not-base58", "Entry 2's entry hash contains characters outside the base58btc alphabet.", ["#read-resolve"],
    { log: g().update({}, { seal: { entryHash: "Qm0OIl" } }).log }, partial("invalid-version-id", 2));
});

// ---- versionTime
group("version-time", () => {
  const g = () => new LogBuilder().genesis();
  vector("plus-zero-offset", "versionTime uses +00:00 instead of Z.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-02T00:00:00+00:00" }).log }, ok({ metadata: { versionNumber: 2 } }));
  vector("fractional-seconds", "versionTime has fractional seconds.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-02T00:00:00.5Z" }).log }, partial("invalid-version-time", 2));
  vector("no-zone", "versionTime has no zone designator.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-02T00:00:00" }).log }, partial("invalid-version-time", 2));
  vector("non-utc-zone", "versionTime uses a +02:00 offset.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-02T02:00:00+02:00" }).log }, partial("invalid-version-time", 2));
  vector("impossible-date", "versionTime is 30 February.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-02-30T00:00:00Z" }).log }, partial("invalid-version-time", 2));
  vector("equal-to-previous", "Entry 2 has the same versionTime as entry 1.", ["#read-resolve"],
    { log: g().update({}, { time: t(1) }).log }, partial("invalid-version-time", 2));
  vector("earlier-than-previous", "Entry 2 is earlier than entry 1.", ["#read-resolve"],
    { log: new LogBuilder().genesis({}, { time: t(5) }).update({}, { time: t(4) }).log }, partial("invalid-version-time", 2));
  vector("one-second-apart", "Entries one second apart are allowed.", ["#the-vh-log-file"],
    { log: g().update({}, { time: t(1, 1) }).log }, ok({ metadata: { versionNumber: 2 } }));
  vector("early-years", "Years 0000–0099 are valid four-digit years.", ["#read-resolve"], {
    log: new LogBuilder().genesis({}, { time: "0000-01-01T00:00:00Z" }).update({}, { time: "0099-12-31T23:59:59Z" })
      .update({}, { time: "0100-03-01T00:00:00Z" }).log,
  }, ok({ metadata: { versionNumber: 3, created: "0000-01-01T00:00:00Z" } }));
  vector("leap-day", "29 February 2000 and 2024 exist.", ["#read-resolve"], {
    log: new LogBuilder().genesis({}, { time: "2000-02-29T12:00:00Z" }).update({}, { time: "2024-02-29T12:00:00Z" }).log,
  }, ok({ metadata: { versionNumber: 2 } }));
  vector("century-not-leap", "29 February 1900 does not exist.", ["#read-resolve"], {
    log: new LogBuilder().genesis({}, { time: "1900-01-01T00:00:00Z" }).update({}, { time: "1900-02-29T00:00:00Z" }).log,
  }, partial("invalid-version-time", 2));
  vector("hour-24", "24:00:00 is not accepted.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-01T24:00:00Z" }).log }, partial("invalid-version-time", 2));
  vector("leap-second", "Second 60 is not accepted.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-01T23:59:60Z" }).log }, partial("invalid-version-time", 2));
  vector("lowercase-z", "A lowercase z zone designator is not accepted.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-01-02T00:00:00z" }).log }, partial("invalid-version-time", 2));
  vector("future-within-tolerance", "versionTime 4 minutes after `now`.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-06-01T00:04:00Z" }).log }, ok({ metadata: { versionNumber: 2 } }));
  vector("future-beyond-tolerance", "versionTime 1 hour after `now`.", ["#read-resolve"],
    { log: g().update({}, { time: "2026-06-01T01:00:00Z" }).log }, partial("future-version-time", 2));
  vector("genesis-in-future", "The genesis versionTime is after `now`.", ["#create"],
    { log: new LogBuilder().genesis({}, { time: "2026-07-01T00:00:00Z" }).log }, bad("future-version-time", 1));
});

// ---- SCID
group("scid", () => {
  vector("scid-in-state-and-parameters", "The SCID placeholder appears in nested state and in a parameter value.",
    ["#create", "#generate-scid"], {
      log: new LogBuilder().genesis(
        { watchers: [`https://watcher.example/${SCID_PLACEHOLDER}`] },
        { state: { id: `example:${SCID_PLACEHOLDER}`, links: [{ self: `example:${SCID_PLACEHOLDER}/a` }] } },
      ).log,
    }, ok());
  const b = new LogBuilder().genesis();
  const otherScid = computeScid({ versionId: SCID_PLACEHOLDER, versionTime: t(1), parameters: { different: true }, state: {} });
  const mismatched = (() => {
    const doc = {
      versionId: otherScid,
      versionTime: t(1),
      parameters: { logVersion: LOG_VERSION, scid: otherScid, updateKeys: [mk("k1")] },
      state: { id: `example:${otherScid}` },
    };
    const signed = { ...doc, versionId: `1-${computeEntryHash(doc, otherScid)}` };
    return serializeEntry({ ...signed, proof: [createProof(signed, KEYS.k1, { created: t(1) })] });
  })();
  vector("scid-mismatch", "The genesis entry is correctly hashed and signed, but its SCID was derived from different content.",
    ["#verify-scid"], { log: mismatched }, bad("scid-mismatch", 1));
  const sha512Scid = (() => {
    const scid = sha512Multihash("genesis");
    const doc = {
      versionId: scid, versionTime: t(1),
      parameters: { logVersion: LOG_VERSION, scid, updateKeys: [mk("k1")] }, state: { id: `example:${scid}` },
    };
    const signed = { ...doc, versionId: `1-${computeEntryHash(doc, scid)}` };
    return serializeEntry({ ...signed, proof: [createProof(signed, KEYS.k1, { created: t(1) })] });
  })();
  vector("sha512-scid", "The SCID is a SHA-512 multihash.", ["#verify-scid"], { log: sha512Scid }, bad("invalid-hash-algorithm", 1));
  vector("genesis-tampered", "The genesis state was changed after sealing; the proof check fails first.",
    ["#verify-scid"], { log: b.fork().tamper((e) => { (e.state as Json).id = "example:{SCID}"; }).log }, bad("invalid-proof", 1));
});

// ---- parameters
group("parameters", () => {
  const g = (p: Json = {}) => new LogBuilder().genesis(p);
  vector("defaults", "Defaults for parameters not set in the genesis entry.", ["#vh-log-parameters"], { log: g().log },
    ok({ metadata: { ttl: 3600, watchers: [], witness: null, deactivated: false, nextKeyHashes: [] } }));
  vector("ttl-and-watchers", "ttl and watchers set at genesis and changed later.", ["#vh-log-parameters"], {
    log: g({ ttl: 60, watchers: ["https://w1.example"] }).update({ watchers: ["https://w2.example"] }).log,
  }, ok({ metadata: { ttl: 60, watchers: ["https://w2.example"] } }));
  vector("ttl-zero", "ttl 0 is allowed.", ["#vh-log-parameters"], { log: g({ ttl: 0 }).log }, ok({ metadata: { ttl: 0 } }));
  vector("unknown-parameter", "A specialisation-defined parameter is ignored.", ["#specialisation-defined-parameters"],
    { log: g({ "example:profile": { anything: [1] } }).update({ "example:other": true }).log }, ok());
  vector("logversion-repeated", "A later entry repeats the same logVersion.", ["#vh-log-parameters"],
    { log: g().update({ logVersion: LOG_VERSION }).log }, ok());
  vector("logversion-missing", "The genesis entry has no logVersion.", ["#vh-log-parameters"], {
    log: new LogBuilder().genesis({ scid: SCID_PLACEHOLDER, updateKeys: [mk("k1")] }, { raw: true }).log,
  }, bad("unsupported-log-version", 1));
  vector("logversion-unknown", "The genesis logVersion is vh-log:0.9.", ["#vh-log-parameters"],
    { log: g({ logVersion: "vh-log:0.9" }).log }, bad("unsupported-log-version", 1));
  vector("logversion-unknown-later", "Entry 2 switches to vh-log:2.0.", ["#vh-log-parameters"],
    { log: g().update({ logVersion: "vh-log:2.0" }).log }, partial("unsupported-log-version", 2));
  vector("scid-missing", "The genesis entry has no scid parameter.", ["#vh-log-parameters"], {
    log: new LogBuilder().genesis({ logVersion: LOG_VERSION, updateKeys: [mk("k1")] }, { raw: true }).log,
  }, bad("invalid-parameter", 1));
  vector("scid-in-later-entry", "Entry 2 repeats scid.", ["#vh-log-parameters"], {
    log: (() => { const b = g(); return b.update({ scid: b.scid }).log; })(),
  }, partial("invalid-parameter", 2));
  vector("update-keys-missing", "The genesis entry has no updateKeys.", ["#vh-log-parameters"], {
    log: new LogBuilder().genesis({ logVersion: LOG_VERSION, scid: SCID_PLACEHOLDER }, { raw: true }).log,
  }, bad("invalid-parameter", 1));
  vector("update-keys-not-multikey", "updateKeys contains a string that is not an Ed25519 multikey.", ["#vh-log-parameters"],
    { log: g().update({ updateKeys: ["not-a-key"] }).log }, partial("invalid-parameter", 2));
  vector("next-key-hashes-not-multihash", "nextKeyHashes contains a non-multihash.", ["#vh-log-parameters"],
    { log: g().update({ nextKeyHashes: ["abc"] }).log }, partial("invalid-parameter", 2));
  vector("null-parameter", "ttl is null.", ["#general-rules-for-parameters"], { log: g().update({ ttl: null }).log },
    partial("invalid-parameter", 2));
  for (const [name, ttl] of [["negative", -1], ["fractional", 1.5], ["string", "60"], ["too-large", 2 ** 31 + 1]] as const) {
    vector(`ttl-${name}`, `ttl is ${JSON.stringify(ttl)}.`, ["#vh-log-parameters"], { log: g().update({ ttl }).log },
      partial("invalid-parameter", 2));
  }
  vector("watchers-valid-forms", "http and https URLs with userinfo, port, path, query and fragment.", ["#vh-log-parameters"], {
    log: g({ watchers: ["http://w.example", "https://u@w.example:8443/a/b?c=d#e", "https://w.example/xn--wtcher-cua/{SCID}"] }).log,
  }, ok());
  for (const [name, url] of [
    ["ftp", "ftp://w.example/log"], ["no-authority", "https://"], ["path-only-authority", "https:///log"],
    ["space", "https://w.example/a b"], ["non-ascii", "https://wätcher.example"], ["uppercase-scheme", "HTTPS://w.example"],
  ] as const) {
    vector(`watchers-${name}`, `watchers contains ${JSON.stringify(url)}.`, ["#vh-log-parameters"],
      { log: g().update({ watchers: [url] }).log }, partial("invalid-parameter", 2));
  }
  vector("deactivated-not-boolean", "deactivated is a string.", ["#vh-log-parameters"],
    { log: g().update({ deactivated: "yes" }).log }, partial("invalid-parameter", 2));
  vector("watchers-not-urls", "watchers contains a non-URL.", ["#vh-log-parameters"],
    { log: g().update({ watchers: ["not a url"] }).log }, partial("invalid-parameter", 2));
  const witnessCases: [string, string, unknown][] = [
    ["threshold-zero", "threshold is 0", { threshold: 0, witnesses: [{ id: did("wA") }] }],
    ["threshold-too-high", "threshold exceeds the number of witnesses", witnessConfig(3, "wA", "wB")],
    ["threshold-missing", "threshold is missing", { witnesses: [{ id: did("wA") }] }],
    ["threshold-fractional", "threshold is 1.5", { threshold: 1.5, witnesses: [{ id: did("wA") }, { id: did("wB") }] }],
    ["duplicate-ids", "the same witness id appears twice", { threshold: 1, witnesses: [{ id: did("wA") }, { id: did("wA") }] }],
    ["duplicate-ids-threshold", "duplicate ids make a threshold of 2 unreachable", { threshold: 2, witnesses: [{ id: did("wA") }, { id: did("wA") }] }],
    ["empty-witnesses", "witnesses is empty", { threshold: 1, witnesses: [] }],
    ["id-not-did-key", "a witness id is not a did:key", { threshold: 1, witnesses: [{ id: "did:example:123" }] }],
  ];
  for (const [name, desc, witness] of witnessCases) {
    vector(`witness-${name}`, `The witness parameter is malformed: ${desc}.`, ["#the-witness-parameter"],
      { log: g().update({ witness }).log }, partial("invalid-parameter", 2));
  }
});

// ---- authorization and proofs
group("authorization", () => {
  const g = () => new LogBuilder().genesis();
  vector("key-rotation", "Entry 2 replaces updateKeys (signed by the old key); entry 3 is signed by the new key.",
    ["#no-key-pre-rotation"], { log: g().update({ updateKeys: [mk("k2")] }).update({}, { signers: ["k2"] }).log },
    ok({ metadata: { updateKeys: [mk("k2")] } }));
  vector("rotation-signed-by-new-key", "Without pre-rotation, entry 2 must be signed by the previous keys, not the ones it introduces.",
    ["#no-key-pre-rotation"], { log: g().update({ updateKeys: [mk("k2")] }, { signers: ["k2"] }).log }, partial("unauthorized-key", 2));
  vector("old-key-after-rotation", "Entry 3 is signed by a key rotated out in entry 2.", ["#no-key-pre-rotation"],
    { log: g().update({ updateKeys: [mk("k2")] }).update({}, { signers: ["k1"] }).log }, partial("unauthorized-key", 3));
  vector("unauthorized-signer", "Entry 2 is signed by an unrelated key.", ["#authorized-keys"],
    { log: g().update({}, { signers: ["attacker"] }).log }, partial("unauthorized-key", 2));
  vector("genesis-unauthorized", "The genesis entry is signed by a key not in its own updateKeys.", ["#authorized-keys"],
    { log: new LogBuilder().genesis({}, { signers: ["k2"] }).log }, bad("unauthorized-key", 1));
  vector("two-keys-two-proofs", "Two update keys, both sign.", ["#authorized-keys"],
    { log: new LogBuilder().genesis({ updateKeys: [mk("k1"), mk("k2")] }, { signers: ["k1", "k2"] }).update({}, { signers: ["k2", "k1"] }).log },
    ok());
  vector("second-proof-unauthorized", "Entry 2 has a valid proof and a second proof from an unauthorized key.", ["#authorized-keys"],
    { log: g().update({}, { signers: ["k1", "attacker"] }).log }, partial("unauthorized-key", 2));
  vector("stop-updates", "Entry 2 sets updateKeys to []; entry 3 cannot be authorised.", ["#deactivate"],
    { log: g().update({ updateKeys: [] }).update({}, { signers: ["k1"] }).log }, partial("unauthorized-key", 3));
  vector("stopped-log-resolves", "A log whose updateKeys is [] still resolves and is not deactivated.", ["#deactivate"],
    { log: g().update({ updateKeys: [] }).log }, ok({ metadata: { deactivated: false, updateKeys: [] } }));
  vector("empty-proof-array", "Entry 2's proof array is empty.", ["#authorized-keys"],
    { log: g().update().tamper((e) => { e.proof = []; }).log }, partial("invalid-proof", 2));
  vector("wrong-cryptosuite", "Entry 2's proof is signed correctly but declares eddsa-rdfc-2022.", ["#authorized-keys"],
    { log: g().update({}, { seal: { proof: { cryptosuite: "eddsa-rdfc-2022" } } }).log }, partial("invalid-proof", 2));
  vector("wrong-proof-purpose", "Entry 2's proof uses proofPurpose authentication.", ["#authorized-keys"],
    { log: g().update({}, { seal: { proof: { proofPurpose: "authentication" } } }).log }, partial("invalid-proof", 2));
  vector("verification-method-not-did-key", "Entry 2's verificationMethod is not a did:key URL.", ["#authorized-keys"],
    { log: g().update({}, { seal: { proof: { verificationMethod: `did:example:123#${mk("k1")}` } } }).log }, partial("invalid-proof", 2));
  vector("verification-method-halves-differ", "Entry 2's verificationMethod fragment names a different key.", ["#authorized-keys"],
    { log: g().update({}, { seal: { proof: { verificationMethod: `did:key:${mk("k1")}#${mk("k2")}` } } }).log }, partial("invalid-proof", 2));
  vector("tampered-state", "Entry 2's state was changed after signing.", ["#authorized-keys"],
    { log: g().update().tamper((e) => { (e.state as Json).version = 99; }).log }, partial("invalid-proof", 2));
  vector("bad-proof-value", "Entry 2's proofValue is not a valid signature.", ["#authorized-keys"],
    { log: g().update().tamper((e) => { (e.proof as Json[])[0].proofValue = "z" + base58btcEncode(new Uint8Array(64)); }).log },
    partial("invalid-proof", 2));
  vector("proof-without-created", "A proof with no `created` property is valid.", ["#authorized-keys"], {
    log: (() => {
      const b = g();
      const prev = b.vid(1);
      const doc = { versionId: prev, versionTime: t(2), parameters: {}, state: { n: 2 } };
      const signed = { ...doc, versionId: `2-${computeEntryHash(doc, prev)}` };
      return b.log + serializeEntry({ ...signed, proof: [createProof(signed, KEYS.k1)] });
    })(),
  }, ok({ state: { n: 2 } }));
});

// ---- pre-rotation
group("pre-rotation", () => {
  const g = () => new LogBuilder().genesis({ nextKeyHashes: [kh("k2")] });
  vector("rotation-chain", "Pre-rotation across three entries; each entry is signed by the key it reveals.", ["#pre-rotation-active"], {
    log: g().update({ updateKeys: [mk("k2")], nextKeyHashes: [kh("k3")] }, { signers: ["k2"] })
      .update({ updateKeys: [mk("k3")], nextKeyHashes: [kh("k4")] }, { signers: ["k3"] }).log,
  }, ok({ metadata: { updateKeys: [mk("k3")], nextKeyHashes: [kh("k4")] } }));
  vector("unused-extra-hashes", "nextKeyHashes commits to more keys than are used.", ["#pre-rotation-key-hash-generation-and-verification"], {
    log: new LogBuilder().genesis({ nextKeyHashes: [kh("k2"), kh("k3")] })
      .update({ updateKeys: [mk("k3")], nextKeyHashes: [kh("k4")] }, { signers: ["k3"] }).log,
  }, ok());
  vector("turn-off", "Entry 2 reveals k2 and sets nextKeyHashes to []; entry 3 follows non-pre-rotation rules (signed by k2, parameters {}).",
    ["#pre-rotation-key-hash-generation-and-verification"], {
      log: g().update({ updateKeys: [mk("k2")], nextKeyHashes: [] }, { signers: ["k2"] }).update({}, { signers: ["k2"] }).log,
    }, ok({ metadata: { nextKeyHashes: [] } }));
  vector("update-keys-omitted", "Pre-rotation is active and entry 2 omits updateKeys.", ["#vh-log-parameters"],
    { log: g().update({ nextKeyHashes: [kh("k3")] }, { signers: ["k1"] }).log }, partial("prerotation-violation", 2));
  vector("next-key-hashes-omitted", "Pre-rotation is active and entry 2 omits nextKeyHashes.", ["#pre-rotation-key-hash-generation-and-verification"],
    { log: g().update({ updateKeys: [mk("k2")] }, { signers: ["k2"] }).log }, partial("prerotation-violation", 2));
  vector("uncommitted-key", "Entry 2 reveals a key whose hash was not committed.", ["#pre-rotation-key-hash-generation-and-verification"],
    { log: g().update({ updateKeys: [mk("attacker")], nextKeyHashes: [] }, { signers: ["attacker"] }).log },
    partial("prerotation-violation", 2));
  vector("one-of-two-uncommitted", "Entry 2 reveals one committed and one uncommitted key.", ["#vh-log-parameters"],
    { log: g().update({ updateKeys: [mk("k2"), mk("k3")], nextKeyHashes: [] }, { signers: ["k2"] }).log },
    partial("prerotation-violation", 2));
  vector("signed-by-previous-key", "With pre-rotation the active keys are the entry's own; signing with the previous key fails.",
    ["#pre-rotation-active"], { log: g().update({ updateKeys: [mk("k2")], nextKeyHashes: [] }, { signers: ["k1"] }).log },
    partial("unauthorized-key", 2));
});

// ---- deactivation
group("deactivation", () => {
  const b = new LogBuilder().genesis().update({ deactivated: true });
  vector("deactivated", "Entry 2 deactivates the log.", ["#deactivate"], { log: b.log },
    ok({ metadata: { deactivated: true, versionNumber: 2 } }));
  vector("deactivated-earlier-version", "Resolving version 1 of a deactivated log still reports it deactivated.", ["#deactivate"],
    { log: b.log, options: { versionNumber: 1 } }, ok({ metadata: { deactivated: true, versionNumber: 1 } }));
  vector("entry-after-deactivation", "An entry follows the deactivating entry.", ["#deactivate"],
    { log: b.fork().update().log }, partial("entry-after-deactivation", 3, { metadata: { deactivated: true } }));
  vector("deactivated-false", "deactivated: false is allowed and does nothing.", ["#vh-log-parameters"],
    { log: new LogBuilder().genesis({ deactivated: false }).update().log }, ok({ metadata: { deactivated: false } }));
});

// ---- witnesses
group("witnesses", () => {
  const W = witnessConfig(2, "wA", "wB", "wC");
  const g = () => new LogBuilder().genesis({ witness: W });
  const one = g();
  vector("genesis-witnessed", "Genesis requires 2 of 3 witnesses and has them.", ["#witness-threshold-algorithm"],
    { log: one.log, witness: witnessFile([one.vid(1), "wA", "wC"]) }, ok({ metadata: { witness: W } }));
  vector("genesis-under-threshold", "Genesis has 1 of the 2 required approvals.", ["#witness-threshold-algorithm"],
    { log: one.log, witness: witnessFile([one.vid(1), "wA"]) }, bad("witness-threshold-not-met", 1));
  vector("witness-file-missing", "Witnesses are required but no witness file was supplied.", ["#verifying-witness-proofs-during-resolution"],
    { log: one.log }, bad("witness-threshold-not-met", 1));
  vector("witness-file-malformed", "The witness file is a JSON object, not an array.", ["#the-witness-proofs-file"],
    { log: one.log, witness: { versionId: one.vid(1) } }, bad("invalid-witness-file", 1));
  vector("duplicate-approvals", "Two proofs from the same witness count once.", ["#witness-threshold-algorithm"],
    { log: one.log, witness: witnessFile([one.vid(1), "wA", "wA"]) }, bad("witness-threshold-not-met", 1));
  vector("unlisted-witness", "A proof from a witness not in the list is ignored.", ["#witness-threshold-algorithm"],
    { log: one.log, witness: witnessFile([one.vid(1), "wA", "wD"]) }, bad("witness-threshold-not-met", 1));
  vector("proof-for-other-version", "A proof signed over a different versionId is filed under this one.", ["#witness-threshold-algorithm"], {
    log: one.log,
    witness: [{ versionId: one.vid(1), proof: [witnessProof(one.vid(1), KEYS.wA), witnessProof("1-QmOther", KEYS.wB)] }],
  }, bad("witness-threshold-not-met", 1));
  const three = g().update().update();
  vector("later-proof-covers-earlier", "Only entry 3 has proofs; they approve entries 1 and 2 too.", ["#the-witness-proofs-file"],
    { log: three.log, witness: witnessFile([three.vid(3), "wA", "wB"]) }, ok({ metadata: { versionNumber: 3 } }));
  vector("unpublished-proofs-ignored", "The witness file has proofs for a versionId not in the log.", ["#the-witness-proofs-file"],
    { log: one.log, witness: witnessFile([one.vid(1), "wA", "wB"], ["2-QmNotPublishedYet", "wA", "wB"]) }, ok());
  vector("last-entry-unwitnessed", "Entries 1–2 are witnessed, entry 3 is not.", ["#verifying-witness-proofs-during-resolution"],
    { log: three.log, witness: witnessFile([three.vid(2), "wA", "wB"], [three.vid(3), "wA"]) },
    partial("witness-threshold-not-met", 3));
  const enable = new LogBuilder().genesis().update({ witness: witnessConfig(1, "wA") });
  vector("enable-later-immediate", "Entry 2 turns witnessing on; the new list applies to entry 2 itself.", ["#vh-log-parameters"],
    { log: enable.log, witness: witnessFile([enable.vid(2), "wA"]) }, ok());
  vector("enable-later-unwitnessed", "Entry 2 turns witnessing on but has no approval.", ["#vh-log-parameters"],
    { log: enable.log, witness: [] }, partial("witness-threshold-not-met", 2));
  const replace = new LogBuilder().genesis({ witness: witnessConfig(1, "wA") })
    .update({ witness: witnessConfig(1, "wB") }).update();
  vector("replace-list", "Entry 2 replaces witness A with B. Entry 2 is witnessed by A; entry 3 by B.", ["#witness-lists"],
    { log: replace.log, witness: witnessFile([replace.vid(2), "wA"], [replace.vid(3), "wB"]) },
    ok({ metadata: { witness: witnessConfig(1, "wB") } }));
  vector("replace-list-new-witness-too-early", "Entry 2 is approved only by the incoming witness B.", ["#witness-lists"],
    { log: replace.log, witness: witnessFile([replace.vid(1), "wA"], [replace.vid(2), "wB"], [replace.vid(3), "wB"]) },
    partial("witness-threshold-not-met", 2));
  const off = new LogBuilder().genesis({ witness: witnessConfig(1, "wA") }).update({ witness: {} }).update();
  vector("turn-off", "Entry 2 sets witness to {}; entry 2 still needs A, entry 3 needs nothing.", ["#vh-log-parameters"],
    { log: off.log, witness: witnessFile([off.vid(2), "wA"]) }, ok({ metadata: { witness: null } }));
  vector("turn-off-unwitnessed", "Entry 2 sets witness to {} but was not approved by A.", ["#vh-log-parameters"],
    { log: off.log, witness: witnessFile([off.vid(1), "wA"]) }, partial("witness-threshold-not-met", 2));
  vector("witness-checked-after-entries", "Entry 2 is invalid (bad hash) and also unwitnessed; the entry error wins and entry 1 stays valid.",
    ["#verifying-witness-proofs-during-resolution"], {
      log: g().update({}, { seal: { entryHash: hashB58("wrong") } }).log,
      witness: witnessFile([one.vid(1), "wA", "wB"]),
    }, partial("entry-hash-mismatch", 2));
});

// ---- version selection
group("selection", () => {
  const b = new LogBuilder().genesis().update().update();
  const s = (n: number) => ({ id: n === 1 ? `example:${b.scid}` : `example:${b.scid}`, ...(n > 1 ? { version: n } : {}) });
  vector("by-version-id", "Select entry 2 by versionId.", ["#selecting-a-version"],
    { log: b.log, options: { versionId: b.vid(2) } }, ok({ state: s(2), metadata: { versionNumber: 2 } }));
  vector("by-version-number", "Select entry 1 by version number.", ["#selecting-a-version"],
    { log: b.log, options: { versionNumber: 1 } }, ok({ metadata: { versionNumber: 1, versionId: b.vid(1) } }));
  vector("by-version-time-between", "A time between entries 2 and 3 selects entry 2.", ["#selecting-a-version"],
    { log: b.log, options: { versionTime: t(2, 30) } }, ok({ metadata: { versionNumber: 2 } }));
  vector("by-version-time-exact", "A time equal to entry 3's selects entry 3.", ["#selecting-a-version"],
    { log: b.log, options: { versionTime: t(3) } }, ok({ metadata: { versionNumber: 3 } }));
  vector("by-version-time-before-genesis", "A time before the genesis entry.", ["#selecting-a-version"],
    { log: b.log, options: { versionTime: "2025-01-01T00:00:00Z" } }, bad("not-found", null));
  vector("version-number-not-found", "Version 9 does not exist.", ["#selecting-a-version"],
    { log: b.log, options: { versionNumber: 9 } }, bad("not-found", null));
  vector("version-id-not-found", "An unknown versionId.", ["#selecting-a-version"],
    { log: b.log, options: { versionId: "2-QmUnknown" } }, bad("not-found", null));
  vector("two-selectors", "versionId and versionNumber together.", ["#selecting-a-version"],
    { log: b.log, options: { versionId: b.vid(1), versionNumber: 1 } }, bad("invalid-option", null));
  vector("unsupported-option", "An option the resolver does not support must fail resolution.", ["#resolution-options"],
    { log: b.log, options: { checkWatchers: 1 } }, bad("invalid-option", null));
  vector("metadata-created-updated", "created/updated are the first and last entry times regardless of the target.", ["#resolution-result"],
    { log: b.log, options: { versionNumber: 2 } }, ok({ metadata: { created: t(1), updated: t(3) } }));
  const broken = new LogBuilder().genesis().update().update({}, { seal: { entryHash: hashB58("wrong") } });
  vector("partial-latest", "Entry 3 is invalid: the latest valid state (entry 2) is returned with a warning.", ["#read-resolve"],
    { log: broken.log }, partial("entry-hash-mismatch", 3, { metadata: { versionNumber: 2, updated: t(2) } }));
  vector("partial-earlier-target", "A valid target before the invalid entry is returned.", ["#read-resolve"],
    { log: broken.log, options: { versionNumber: 1 } }, partial("entry-hash-mismatch", 3, { metadata: { versionNumber: 1 } }));
  vector("partial-invalid-target-number", "Selecting the invalid entry by number fails.", ["#read-resolve"],
    { log: broken.log, options: { versionNumber: 3 } }, bad("entry-hash-mismatch", 3));
  vector("partial-invalid-target-id", "Selecting the invalid entry by versionId fails.", ["#read-resolve"],
    { log: broken.log, options: { versionId: broken.vid(3) } }, bad("entry-hash-mismatch", 3));
  vector("partial-invalid-target-time", "Selecting a time at which the invalid entry was active fails.", ["#read-resolve"],
    { log: broken.log, options: { versionTime: t(4) } }, bad("entry-hash-mismatch", 3));
});

// ---- copies
group("copies", () => {
  const full = new LogBuilder().genesis().update().update().update();
  const forked = full.truncate(2).update({}, { state: { forked: true } });
  const src = (s: string) => `https://${s}.example/log`;
  const copy = (source: string, b: LogBuilder) => ({ source: src(source), log: b.log });
  vector("identical-copy", "A watcher has the same log.", ["#comparing-copies-of-a-log"],
    { log: full.log, copies: [copy("w1", full)] }, ok({ metadata: { versionNumber: 4 } }));
  vector("behind-copy", "A watcher is two entries behind.", ["#comparing-copies-of-a-log"],
    { log: full.log, copies: [copy("w1", full.truncate(2))] }, ok({ warnings: ["copy-behind"] }));
  vector("primary-behind", "The primary copy is behind; a longer copy extends it and becomes the reference.", ["#comparing-copies-of-a-log"],
    { log: full.truncate(3).log, copies: [copy("w1", full)] }, ok({ metadata: { versionNumber: 4 }, warnings: ["copy-behind"] }));
  const unauthorized = full.truncate(3).update({}, { signers: ["attacker"], state: { attacker: true } });
  vector("invalid-copy", "A watcher's copy diverges at entry 4 with an entry signed by an unauthorised key.", ["#comparing-copies-of-a-log"],
    { log: full.log, copies: [copy("w1", unauthorized)] }, ok({ warnings: ["copy-invalid"] }));
  vector("tampered-copy-same-version-ids",
    "A copy whose last versionId matches the reference is not re-verified, so an edited state behind an unchanged versionId still counts as matching. This is what the spec says; see docs/spec-notes.md.",
    ["#comparing-copies-of-a-log"],
    { log: full.log, copies: [copy("w1", full.fork().tamper((e) => { (e.state as Json).version = 99; }))] }, ok({ warnings: [] }));
  vector("unavailable-copy", "A watcher could not be reached.", ["#resolution-options"],
    { log: full.log, copies: [{ source: src("w1"), unavailable: "connection refused" }] }, ok({ warnings: ["copy-unavailable"] }));
  vector("fork", "A watcher holds a validly signed log that diverges at entry 3.", ["#comparing-copies-of-a-log"],
    { log: full.log, copies: [copy("w1", forked)] }, bad("fork-detected", 3));
  vector("fork-earlier-target", "A fork fails resolution even for a version before the divergence.", ["#comparing-copies-of-a-log"],
    { log: full.log, options: { versionNumber: 1 }, copies: [copy("w1", forked)] }, bad("fork-detected", 3));
  vector("fork-shorter-primary", "The primary is a shorter fork of a watcher's log.", ["#comparing-copies-of-a-log"],
    { log: forked.log, copies: [copy("w1", full)] }, bad("fork-detected", 3));
  vector("invalid-primary", "The primary copy is tampered; the watcher's copy becomes the reference.", ["#comparing-copies-of-a-log"], {
    log: full.fork().tamper((e) => { (e.state as Json).version = 99; }).log,
    copies: [copy("w1", full)],
  }, ok({ metadata: { versionNumber: 4 }, warnings: ["copy-invalid"] }));
  vector("min-copies-met", "minCopies 2 is met by a behind copy.", ["#resolution-options"],
    { log: full.log, options: { minCopies: 2 }, copies: [copy("w1", full.truncate(3))] }, ok({ warnings: ["copy-behind"] }));
  vector("min-copies-not-met", "minCopies 2 with only an unavailable and an invalid copy.", ["#resolution-options"], {
    log: full.log, options: { minCopies: 2 },
    copies: [{ source: src("w1"), unavailable: "timeout" }, copy("w2", unauthorized)],
  }, bad("min-copies-not-met", null));
  vector("min-copies-no-copies", "minCopies 2 with no other copies supplied.", ["#resolution-options"],
    { log: full.log, options: { minCopies: 2 } }, bad("min-copies-not-met", null));
  vector("retained-match", "A retained versionId from an earlier resolution matches.", ["#comparing-copies-of-a-log"],
    { log: full.log, retainedVersionId: full.vid(3) }, ok());
  vector("retained-fork", "A retained versionId differs from the log at the same version.", ["#comparing-copies-of-a-log"],
    { log: full.log, retainedVersionId: forked.vid(3) }, bad("fork-detected", 3));
  vector("retained-not-found", "The log is shorter than the retained version (truncation or rollback).", ["#comparing-copies-of-a-log"],
    { log: full.truncate(2).log, retainedVersionId: full.vid(4) }, ok({ warnings: ["retained-version-not-found"] }));
  vector("retained-with-copies", "A retained versionId checked against the reference chosen from several copies.", ["#comparing-copies-of-a-log"],
    { log: full.truncate(2).log, copies: [copy("w1", full)], retainedVersionId: full.vid(4) }, ok({ warnings: ["copy-behind"] }));
});

// ---------------------------------------------------------------- primitives

function primitives() {
  const jcsTexts = [
    '{"b":1,"a":[true,null,false]}',
    '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,-0,1.0,100,1e21,1e-7,0.1,5e-324,1.7976931348623157e308]}',
    '{"doubles":[896365914996807.2,0.30000000000000004,4.35,2.2250738585072014e-308,9.999999999999999e22,1e22,123e-20,1e-6,1e20,295147905179352830000,0.000001234,1.5e-9,-1e-7]}',
    '{"big":123456789012345678,"bigger":9007199254740993}',
    '{"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","del":"\\u007f","ls":"\\u2028"}',
    '{"\\u20ac":"Euro","\\r":"CR","\\ufb33":"Hebrew","1":"One","\\ud83d\\ude00":"Smiley","\\u0080":"Control","\\u00f6":"Latin","a":"lower","A":"upper"}',
    '{"nested":{"z":{"y":[{"b":2,"a":1}]},"a":[]},"empty":{}}',
    '"top-level string"',
    "[1,[2,[3]],{}]",
  ];
  const seeds = ["00".repeat(32), "01".repeat(32), "ff".repeat(32), KEYS.k1, KEYS.k2];
  const prelim = {
    versionId: SCID_PLACEHOLDER,
    versionTime: t(1),
    parameters: { logVersion: LOG_VERSION, scid: SCID_PLACEHOLDER, updateKeys: [mk("k1")] },
    state: { id: `example:${SCID_PLACEHOLDER}` },
  };
  const scid = computeScid(prelim);
  const entry = JSON.parse(JSON.stringify(prelim).replaceAll(SCID_PLACEHOLDER, scid));
  const specExample = {
    versionId: "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", versionTime: "2025-04-01T17:39:50Z",
    parameters: {
      witness: { threshold: 2, witnesses: [{ id: "witness-1" }, { id: "witness-2" }, { id: "witness-3" }] },
      updateKeys: ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"],
      nextKeyHashes: ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"],
      logVersion: "vh-log:1.0", scid: "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE",
    },
    state: { id: "example:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE" },
  };
  const doc = { versionId: "1-QmExample", hello: "world" };
  const signCases = [
    { document: doc, seed: KEYS.k1, created: t(1) },
    { document: doc, seed: KEYS.k2 },
    { document: { versionId: "2-QmWitnessed" }, seed: KEYS.wA, created: t(2) },
  ];
  return {
    description: "Primitive operation vectors. `jcs` inputs are raw JSON text, parsed by the implementation itself.",
    jcs: jcsTexts.map((text) => ({ text, output: canonicalize(JSON.parse(text)) })),
    hash: ["", "abc", "{SCID}", "€😀"].map((data) => ({ data, output: hashB58(data) })),
    multikey: seeds.map((s) => ({ seed: s, multikey: signerFromSeed(s).multikey })),
    keyHash: seeds.map((s) => {
      const multikey = signerFromSeed(s).multikey;
      return { multikey, output: keyHash(multikey) };
    }),
    scid: [{ entry: prelim, scid }],
    entryHash: [
      { entry, previousVersionId: scid, hash: computeEntryHash(entry, scid) },
      {
        description: "The example from the spec's Generate Entry Hash section. The spec states QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ, which does not reproduce (see docs/spec-notes.md).",
        entry: specExample, previousVersionId: specExample.versionId, hash: computeEntryHash(specExample, specExample.versionId),
      },
    ],
    sign: signCases.map((c) => ({
      ...c,
      proof: createProof(c.document, c.seed, c.created ? { created: c.created } : {}),
    })),
  };
}

// ---------------------------------------------------------------- generation scenarios

function generation() {
  type Step = { op: "create" | "update"; input: Json };
  const s = (name: string) => KEYS[name];
  const scenarios: { name: string; description: string; steps: Step[]; witness?: { step: number; seeds: string[] }[] }[] = [
    {
      name: "minimal",
      description: "Create a log and update it once.",
      steps: [
        { op: "create", input: { state: { id: "example:{SCID}" }, parameters: { updateKeys: [mk("k1")] }, versionTime: t(1), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", name: "renamed" }, parameters: {}, versionTime: t(2), signers: [s("k1")] } },
      ],
    },
    {
      name: "rotation-and-parameters",
      description: "Key rotation without pre-rotation, ttl, watchers and a specialisation-defined parameter.",
      steps: [
        { op: "create", input: { state: { id: "example:{SCID}", list: [1, 2, 3] }, parameters: { updateKeys: [mk("k1")], ttl: 300, watchers: ["https://watcher.example/{SCID}"], "example:custom": { a: 1 } }, versionTime: t(1), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", list: [] }, parameters: { updateKeys: [mk("k2")] }, versionTime: t(2), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", list: [4] }, parameters: { ttl: 0, watchers: [] }, versionTime: t(3), signers: [s("k2")] } },
      ],
    },
    {
      name: "pre-rotation",
      description: "Pre-rotation through three keys, then turned off.",
      steps: [
        { op: "create", input: { state: { id: "example:{SCID}" }, parameters: { updateKeys: [mk("k1")], nextKeyHashes: [kh("k2")] }, versionTime: t(1), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", v: 2 }, parameters: { updateKeys: [mk("k2")], nextKeyHashes: [kh("k3"), kh("k4")] }, versionTime: t(2), signers: [s("k2")] } },
        { op: "update", input: { state: { id: "example:{SCID}", v: 3 }, parameters: { updateKeys: [mk("k4")], nextKeyHashes: [] }, versionTime: t(3), signers: [s("k4")] } },
        { op: "update", input: { state: { id: "example:{SCID}", v: 4 }, parameters: {}, versionTime: t(4), signers: [s("k4")] } },
      ],
    },
    {
      name: "witnessed",
      description: "Witnessed from genesis, witness list replaced, then witnessing turned off.",
      steps: [
        { op: "create", input: { state: { id: "example:{SCID}" }, parameters: { updateKeys: [mk("k1")], witness: witnessConfig(2, "wA", "wB", "wC") }, versionTime: t(1), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", v: 2 }, parameters: { witness: witnessConfig(1, "wD") }, versionTime: t(2), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", v: 3 }, parameters: { witness: {} }, versionTime: t(3), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", v: 4 }, parameters: {}, versionTime: t(4), signers: [s("k1")] } },
      ],
      witness: [{ step: 2, seeds: [s("wA"), s("wC")] }, { step: 3, seeds: [s("wD")] }],
    },
    {
      name: "multi-signer-deactivated",
      description: "Two update keys, both signing, then deactivation.",
      steps: [
        { op: "create", input: { state: { id: "example:{SCID}" }, parameters: { updateKeys: [mk("k1"), mk("k2")] }, versionTime: t(1), signers: [s("k1"), s("k2")] } },
        { op: "update", input: { state: { id: "example:{SCID}", closed: true }, parameters: { deactivated: true }, versionTime: t(2), signers: [s("k2")] } },
      ],
    },
    {
      name: "unicode-and-numbers",
      description: "State exercising JCS string escaping, key ordering and number serialisation.",
      steps: [
        { op: "create", input: { state: { id: "example:{SCID}", "€": "euro", "😀": "smile", "דּ": "dalet", text: "line\nbreak \"quoted\" \u0001", n: [0.1, 1e21, 1e-7, -1.5, 100] }, parameters: { updateKeys: [mk("k1")] }, versionTime: t(1), signers: [s("k1")] } },
        { op: "update", input: { state: { id: "example:{SCID}", "ö": { "é": [true, false, null] } }, parameters: {}, versionTime: t(2), signers: [s("k1")] } },
      ],
    },
  ];

  return {
    description: "Generation scenarios. Run the steps in order, threading `log` from each step's output into the next `update`. `{SCID}` in an update's state is replaced by the harness with the SCID returned by `create`. Compare each new line, parsed, to `expect.line`. Then produce witness proofs and resolve.",
    scenarios: scenarios.map((sc) => {
      let log = "";
      let scid = "";
      const steps = sc.steps.map((step) => {
        let result: { log: string; versionId: string; scid?: string };
        if (step.op === "create") {
          result = createLogWith(step.input);
          scid = result.scid!;
        } else {
          const input = JSON.parse(JSON.stringify(step.input).replaceAll(SCID_PLACEHOLDER, scid));
          result = updateLogWith({ ...input, log });
        }
        log = result.log;
        const line = JSON.parse(log.trimEnd().split("\n").at(-1)!);
        return { ...step, expect: { versionId: result.versionId, ...(result.scid ? { scid: result.scid } : {}), line } };
      });
      const versionIds = steps.map((st) => st.expect.versionId);
      const witnessFileOut = (sc.witness ?? []).map((w) => ({
        versionId: versionIds[w.step - 1],
        proof: w.seeds.map((seedHex) => witnessProof(versionIds[w.step - 1], seedHex)),
      }));
      const resolved = resolve({ log, witness: sc.witness ? witnessFileOut : undefined, now: NOW });
      if (!resolved.valid || resolved.error) throw new Error(`scenario ${sc.name} does not resolve: ${JSON.stringify(resolved)}`);
      return {
        name: sc.name,
        description: sc.description,
        steps,
        ...(sc.witness ? { witness: sc.witness, witnessFile: witnessFileOut } : {}),
        log,
        resolve: { now: NOW, state: resolved.state, versionId: resolved.metadata.versionId },
      };
    }),
  };
}

const createLogWith = (i: Json) => createLog(i as never);
const updateLogWith = (i: Json) => updateLog(i as never);

// ---------------------------------------------------------------- write

function write(path: string, value: unknown) {
  const file = join(OUT, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
}

write("primitives.json", primitives());
write("generation.json", generation());
let total = 0;
for (const [name, cases] of Object.entries(groups)) {
  write(`resolution/${name}.json`, { description: `Resolution vectors: ${name}.`, cases });
  total += cases.length;
}
write("keys.json", {
  description: "Ed25519 seeds (hex) used by the vectors. Test keys only — never use them for anything real.",
  keys: Object.fromEntries(Object.entries(KEYS).map(([n, s]) => [n, { seed: s, multikey: mk(n), keyHash: kh(n) }])),
});
console.log(`wrote ${total} resolution vectors in ${Object.keys(groups).length} groups`);
