import { publicKeyFromMultikey } from "./encoding.ts";
import { VHLogError, type ErrorReport } from "./errors.ts";
import { checkSha256Multihash, keyHash } from "./hash.ts";
import { computeEntryHash, computeScid, LOG_VERSION, parseLogLines, SCID_PLACEHOLDER, type LogEntry } from "./log.ts";
import { multikeyFromVerificationMethod, verifyProof } from "./proof.ts";

/** Seconds a `versionTime` may be ahead of the resolver's clock (profile §4). */
export const FUTURE_TOLERANCE_SECONDS = 300;
const SUPPORTED_LOG_VERSIONS = [LOG_VERSION];
const ENTRY_KEYS = ["versionId", "versionTime", "parameters", "state", "proof"];

export interface WitnessConfig {
  threshold: number;
  witnesses: { id: string }[];
}

export interface Parameters {
  logVersion: string;
  scid: string;
  updateKeys: string[];
  nextKeyHashes: string[];
  /** null when the parameter is `{}` (no witnesses). */
  witness: WitnessConfig | null;
  watchers: string[];
  deactivated: boolean;
  ttl: number;
}

export interface VerifiedEntry {
  entry: LogEntry;
  versionNumber: number;
  /** Milliseconds since the epoch. */
  time: number;
  /** Parameters active after this entry. */
  parameters: Parameters;
  /** Witness list this entry must satisfy, or null if it needs no witnessing. */
  witnessRule: WitnessConfig | null;
}

export interface VerifiedLog {
  /** The valid (and witnessed) prefix of the log. */
  entries: VerifiedEntry[];
  /** The raw lines of the log, for copy comparison. */
  lines: string[];
  failure: ErrorReport | null;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

/** Parses a `versionTime`; returns null unless it is a whole-second UTC timestamp (profile §4). */
export function parseVersionTime(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:Z|\+00:00)$/.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (days === undefined || d < 1 || d > days || h > 23 || mi > 59 || s > 59) return null;
  // Date.UTC maps years 0–99 to 1900–1999, so set the full year explicitly.
  const date = new Date(0);
  date.setUTCFullYear(y, mo - 1, d);
  date.setUTCHours(h, mi, s, 0);
  return date.getTime();
}

/**
 * Profile §4: an `http` or `https` URL made only of printable ASCII
 * (U+0021–U+007E), with a non-empty authority.
 */
export function isWatcherUrl(value: string): boolean {
  if (!/^[\x21-\x7e]+$/.test(value)) return false;
  const rest = value.startsWith("https://") ? value.slice(8) : value.startsWith("http://") ? value.slice(7) : null;
  return rest !== null && /^[^/?#]/.test(rest);
}

/** Profile §4: a log line must be I-JSON-safe — finite numbers and well-formed Unicode strings. */
function isSafeJson(value: unknown): boolean {
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return value.isWellFormed();
  if (Array.isArray(value)) return value.every(isSafeJson);
  if (isObject(value)) return Object.entries(value).every(([k, v]) => k.isWellFormed() && isSafeJson(v));
  return true;
}

function validateWitness(value: unknown, version: number): WitnessConfig | null {
  const fail = (why: string) => new VHLogError("invalid-parameter", `witness: ${why}`, version);
  if (!isObject(value)) throw fail("must be an object");
  if (Object.keys(value).length === 0) return null;
  const { threshold, witnesses } = value;
  if (!Array.isArray(witnesses) || witnesses.length === 0) throw fail("witnesses must be a non-empty array");
  const ids = new Set<string>();
  for (const w of witnesses) {
    if (!isObject(w) || typeof w.id !== "string") throw fail("each witness needs a string id");
    if (!w.id.startsWith("did:key:") || !publicKeyFromMultikey(w.id.slice("did:key:".length))) {
      throw fail(`witness id ${w.id} is not an Ed25519 did:key`);
    }
    const id = w.id.normalize("NFC");
    if (ids.has(id)) throw fail(`duplicate witness id ${w.id}`);
    ids.add(id);
  }
  if (typeof threshold !== "number" || !Number.isInteger(threshold) || threshold < 1 || threshold > ids.size) {
    throw fail("threshold must be an integer between 1 and the number of witnesses");
  }
  return { threshold, witnesses: witnesses as { id: string }[] };
}

/** Applies an entry's `parameters` to the previously active set (Read step 1 and the pre-rotation rule of step 7). */
function applyParameters(raw: Record<string, unknown>, previous: Parameters | null, version: number): Parameters {
  const invalid = (msg: string) => new VHLogError("invalid-parameter", msg, version);
  for (const [key, value] of Object.entries(raw)) {
    if (value === null) throw invalid(`${key} must not be null`);
  }
  if (previous === null) {
    if (!("logVersion" in raw)) throw new VHLogError("unsupported-log-version", "logVersion missing from first entry", 1);
  }
  if ("logVersion" in raw) {
    if (typeof raw.logVersion !== "string" || !SUPPORTED_LOG_VERSIONS.includes(raw.logVersion)) {
      throw new VHLogError("unsupported-log-version", `unsupported logVersion ${JSON.stringify(raw.logVersion)}`, version);
    }
    if (previous && SUPPORTED_LOG_VERSIONS.indexOf(raw.logVersion) < SUPPORTED_LOG_VERSIONS.indexOf(previous.logVersion)) {
      throw new VHLogError("unsupported-log-version", "logVersion may not be lowered", version);
    }
  }
  if (previous === null) {
    if (typeof raw.scid !== "string") throw invalid("scid missing from first entry");
    if (!("updateKeys" in raw)) throw invalid("updateKeys missing from first entry");
  } else if ("scid" in raw) {
    throw invalid("scid may only appear in the first entry");
  }
  if ("updateKeys" in raw) {
    if (!isStringArray(raw.updateKeys) || raw.updateKeys.some((k) => !publicKeyFromMultikey(k))) {
      throw invalid("updateKeys must be an array of Ed25519 multikeys");
    }
  }
  if ("nextKeyHashes" in raw) {
    if (!isStringArray(raw.nextKeyHashes) || raw.nextKeyHashes.some((h) => checkSha256Multihash(h) !== "ok")) {
      throw invalid("nextKeyHashes must be an array of SHA-256 multihashes");
    }
  }
  const witness = "witness" in raw ? validateWitness(raw.witness, version) : previous?.witness ?? null;
  if ("watchers" in raw) {
    if (!isStringArray(raw.watchers) || raw.watchers.some((u) => !isWatcherUrl(u))) {
      throw invalid("watchers must be an array of URLs");
    }
  }
  if ("deactivated" in raw && typeof raw.deactivated !== "boolean") throw invalid("deactivated must be a boolean");
  if ("ttl" in raw) {
    const ttl = raw.ttl;
    if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 0 || ttl > 2 ** 31) {
      throw invalid("ttl must be an integer between 0 and 2^31");
    }
  }

  if (previous && previous.nextKeyHashes.length > 0) {
    const violation = (msg: string) => new VHLogError("prerotation-violation", msg, version);
    if (!("updateKeys" in raw)) throw violation("updateKeys must be explicit while pre-rotation is active");
    if (!("nextKeyHashes" in raw)) throw violation("nextKeyHashes must be explicit while pre-rotation is active");
    for (const key of raw.updateKeys as string[]) {
      if (!previous.nextKeyHashes.includes(keyHash(key))) throw violation(`key ${key} was not committed`);
    }
  }

  return {
    logVersion: (raw.logVersion as string | undefined) ?? previous!.logVersion,
    scid: (raw.scid as string | undefined) ?? previous!.scid,
    updateKeys: (raw.updateKeys as string[] | undefined) ?? previous!.updateKeys,
    nextKeyHashes: (raw.nextKeyHashes as string[] | undefined) ?? previous?.nextKeyHashes ?? [],
    witness,
    watchers: (raw.watchers as string[] | undefined) ?? previous?.watchers ?? [],
    deactivated: (raw.deactivated as boolean | undefined) ?? false,
    ttl: (raw.ttl as number | undefined) ?? previous?.ttl ?? 3600,
  };
}

function verifyProofs(entry: Record<string, unknown>, activeKeys: string[], version: number): void {
  const proofs = entry.proof as unknown[];
  if (proofs.length === 0) throw new VHLogError("invalid-proof", "proof array is empty", version);
  const { proof: _, ...document } = entry;
  for (const proof of proofs) {
    const multikey = isObject(proof) ? multikeyFromVerificationMethod(proof.verificationMethod) : null;
    if (!multikey) throw new VHLogError("invalid-proof", "proof verificationMethod is not did:key:<mk>#<mk>", version);
    if (!activeKeys.includes(multikey)) {
      throw new VHLogError("unauthorized-key", `${multikey} is not an active update key`, version);
    }
    if (!verifyProof(document, proof)) throw new VHLogError("invalid-proof", "proof failed verification", version);
  }
}

function verifyVersionId(entry: Record<string, unknown>, expectedNumber: number, previousVersionId: string): void {
  const versionId = entry.versionId as string;
  const m = /^([1-9][0-9]*)-([^-]+)$/.exec(versionId);
  if (!m || Number(m[1]) !== expectedNumber) {
    throw new VHLogError("invalid-version-id", `expected versionId ${expectedNumber}-<hash>, got ${versionId}`, expectedNumber);
  }
  const check = checkSha256Multihash(m[2]);
  if (check === "not-base58") throw new VHLogError("invalid-version-id", "entry hash is not base58btc", expectedNumber);
  if (check === "unsupported-algorithm") {
    throw new VHLogError("invalid-hash-algorithm", "entry hash is not a SHA-256 multihash", expectedNumber);
  }
  if (computeEntryHash(entry, previousVersionId) !== m[2]) {
    throw new VHLogError("entry-hash-mismatch", "entry hash does not match", expectedNumber);
  }
}

function verifyScid(entry: Record<string, unknown>, scid: string): void {
  const check = checkSha256Multihash(scid);
  if (check === "unsupported-algorithm") throw new VHLogError("invalid-hash-algorithm", "SCID is not a SHA-256 multihash", 1);
  if (check === "not-base58") throw new VHLogError("scid-mismatch", "SCID is not base58btc", 1);
  const { proof: _, ...rest } = entry;
  const text = JSON.stringify({ ...rest, versionId: SCID_PLACEHOLDER }).replaceAll(scid, SCID_PLACEHOLDER);
  if (computeScid(JSON.parse(text)) !== scid) throw new VHLogError("scid-mismatch", "SCID does not match", 1);
}

/** Runs the per-entry checks (profile §4, steps 1–7) on one parsed line. */
function verifyEntry(raw: unknown, previous: VerifiedEntry | null, now: number): VerifiedEntry {
  const version = previous ? previous.versionNumber + 1 : 1;
  if (previous?.parameters.deactivated) {
    throw new VHLogError("entry-after-deactivation", "entry follows a deactivating entry", version);
  }
  if (
    !isObject(raw) || Object.keys(raw).length !== ENTRY_KEYS.length || !ENTRY_KEYS.every((k) => k in raw) ||
    typeof raw.versionId !== "string" || typeof raw.versionTime !== "string" || !isObject(raw.parameters) ||
    !isObject(raw.state) || !Array.isArray(raw.proof)
  ) {
    throw new VHLogError("invalid-entry", "entry does not have the required properties and types", version);
  }
  const parameters = applyParameters(raw.parameters, previous?.parameters ?? null, version);

  let activeKeys: string[];
  let witnessRule: WitnessConfig | null;
  if (!previous) {
    activeKeys = parameters.updateKeys;
    witnessRule = parameters.witness;
  } else {
    activeKeys = previous.parameters.nextKeyHashes.length > 0 ? parameters.updateKeys : previous.parameters.updateKeys;
    const enablesWitnesses = "witness" in raw.parameters && previous.parameters.witness === null;
    witnessRule = enablesWitnesses ? parameters.witness : previous.parameters.witness;
  }
  verifyProofs(raw, activeKeys, version);
  verifyVersionId(raw, version, previous ? previous.entry.versionId : parameters.scid);

  const time = parseVersionTime(raw.versionTime);
  if (time === null) throw new VHLogError("invalid-version-time", `invalid versionTime ${raw.versionTime}`, version);
  if (previous && time <= previous.time) {
    throw new VHLogError("invalid-version-time", "versionTime must be later than the previous entry's", version);
  }
  if (time > now + FUTURE_TOLERANCE_SECONDS * 1000) {
    throw new VHLogError("future-version-time", "versionTime is in the future", version);
  }
  if (!previous) verifyScid(raw, parameters.scid);

  return { entry: raw as unknown as LogEntry, versionNumber: version, time, parameters, witnessRule };
}

function asWitnessFile(witness: unknown): { versionId: string; proof: unknown[] }[] | null {
  if (!Array.isArray(witness)) return null;
  for (const item of witness) {
    if (!isObject(item) || typeof item.versionId !== "string" || !Array.isArray(item.proof)) return null;
  }
  return witness as { versionId: string; proof: unknown[] }[];
}

/** Returns the index of the first entry that is not witnessed, or -1 (Verifying Witness Proofs During Resolution). */
function checkWitnesses(entries: VerifiedEntry[], witness: unknown): { index: number; error: VHLogError } | null {
  const first = entries.findIndex((e) => e.witnessRule !== null);
  if (first === -1) return null;
  const file = witness === undefined ? [] : asWitnessFile(witness);
  if (file === null) {
    return { index: first, error: new VHLogError("invalid-witness-file", "witness file is malformed", first + 1) };
  }
  const position = new Map(entries.map((e, i) => [e.entry.versionId, i]));
  // Verified (witness id, entry index) approvals; a proof for entry j approves every entry <= j.
  const approvals: { id: string; index: number; proof: unknown; versionId: string }[] = [];
  for (const record of file) {
    const index = position.get(record.versionId);
    if (index === undefined) continue;
    for (const proof of record.proof) {
      const multikey = isObject(proof) ? multikeyFromVerificationMethod(proof.verificationMethod) : null;
      if (multikey) approvals.push({ id: `did:key:${multikey}`.normalize("NFC"), index, proof, versionId: record.versionId });
    }
  }
  const verified = new Map<unknown, boolean>();
  const isValid = (a: (typeof approvals)[number]) => {
    if (!verified.has(a.proof)) verified.set(a.proof, verifyProof({ versionId: a.versionId }, a.proof));
    return verified.get(a.proof)!;
  };
  for (let i = first; i < entries.length; i++) {
    const rule = entries[i].witnessRule;
    if (!rule) continue;
    const ids = new Set(rule.witnesses.map((w) => w.id.normalize("NFC")));
    const approved = new Set<string>();
    for (const a of approvals) {
      if (a.index >= i && ids.has(a.id) && !approved.has(a.id) && isValid(a)) approved.add(a.id);
    }
    if (approved.size < rule.threshold) {
      const error = new VHLogError(
        "witness-threshold-not-met",
        `entry ${i + 1} has ${approved.size} of ${rule.threshold} required witness approvals`,
        i + 1,
      );
      return { index: i, error };
    }
  }
  return null;
}

/** Verifies a whole log file, returning its valid, witnessed prefix and the first failure. */
export function verifyLog(log: string, witness: unknown, now: number): VerifiedLog {
  const lines = parseLogLines(log);
  const entries: VerifiedEntry[] = [];
  let failure: ErrorReport | null = null;
  if (lines.length === 0) {
    return { entries, lines, failure: { code: "invalid-log", version: null, message: "log is empty" } };
  }
  for (let i = 0; i < lines.length; i++) {
    try {
      let raw: unknown;
      try {
        raw = JSON.parse(lines[i]);
      } catch {
        throw new VHLogError("invalid-log", `line ${i + 1} is not JSON`, i + 1);
      }
      if (!isObject(raw)) throw new VHLogError("invalid-log", `line ${i + 1} is not a JSON object`, i + 1);
      if (!isSafeJson(raw)) {
        throw new VHLogError("invalid-log", `line ${i + 1} has a non-finite number or a lone surrogate`, i + 1);
      }
      entries.push(verifyEntry(raw, entries.at(-1) ?? null, now));
    } catch (e) {
      if (!(e instanceof VHLogError)) throw e;
      failure = e.toReport();
      break;
    }
  }
  const unwitnessed = checkWitnesses(entries, witness);
  if (unwitnessed) {
    entries.length = unwitnessed.index;
    failure = unwitnessed.error.toReport();
  }
  return { entries, lines, failure };
}
