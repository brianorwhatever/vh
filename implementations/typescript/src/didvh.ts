// did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
// verification as a VH-Log log (did:vh and VH-Log are both derived from
// did:webvh), so the log is verified by the VH-Log code with the DID_VH
// specialisation. This module adds the DID syntax, the srcLog/srcWitness and
// DID URL rules, the resolution options, and DID Resolution metadata and errors.
import { VHLogError, type ErrorReport } from "./errors.ts";
import { createLog, parseLogLines, SCID_PLACEHOLDER, updateLog, type UpdateInput } from "./log.ts";
import { resolve } from "./resolve.ts";
import { isWatcherUrl, parseVersionTime, verifyLog, type Specialisation, type WitnessConfig } from "./verify.ts";

export const DID_VH_METHOD = "did:vh:1.0";
/** A well-formed `method` value: `did:vh:<major>.<minor>`, no leading zeros. */
const METHOD_SYNTAX = /^did:vh:(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
export const DID_PREFIX = "did:vh:";

/** did:vh error codes (DID Resolution, plus the did:vh-specific ones). */
export type DidVhErrorCode =
  | "invalidDid"
  | "invalidDidUrl"
  | "invalidOptions"
  | "notFound"
  | "featureNotSupported"
  | "logForked"
  | "insufficientCopies";

export class DidVhError extends Error {
  readonly code: DidVhErrorCode;
  readonly vhLog?: ErrorReport;

  constructor(code: DidVhErrorCode, message: string, vhLog?: ErrorReport) {
    super(message);
    this.code = code;
    this.vhLog = vhLog;
  }
}

// ---------------------------------------------------------------- the DID

const SCID_RE = /^[1-9A-HJ-NP-Za-km-z]{46}$/;

/** The SCID of a did:vh DID, or null if `did` does not match the ABNF. */
export function parseDid(did: unknown): string | null {
  if (typeof did !== "string" || !did.startsWith(DID_PREFIX)) return null;
  const scid = did.slice(DID_PREFIX.length);
  return SCID_RE.test(scid) ? scid : null;
}

/**
 * The did:vh specialisation of VH-Log: `method` instead of `logVersion`, a
 * closed parameter set, and `state.id` = `did:vh:<SCID>` in every entry. With
 * `expectedScid`, the log's SCID must also be that of the DID being resolved.
 */
export function didVhSpecialisation(expectedScid?: string): Specialisation {
  return {
    versionParameter: "method",
    versions: [DID_VH_METHOD],
    versionSyntax: METHOD_SYNTAX,
    extraParameters: [],
    checkState(state, scid, version) {
      if (expectedScid !== undefined && scid !== expectedScid) {
        throw new VHLogError("invalid-state", `the log is for did:vh:${scid}, not did:vh:${expectedScid}`, version);
      }
      if (state.id !== DID_PREFIX + scid) {
        throw new VHLogError("invalid-state", `state.id must be ${DID_PREFIX}${scid}`, version);
      }
    },
  };
}

export const DID_VH = didVhSpecialisation();

// ---------------------------------------------------------------- create / update

export interface CreateDidInput {
  /** The DID document, using `did:vh:{SCID}` wherever it refers to the DID. */
  document: Record<string, unknown>;
  /** VH-Log parameters; `method` and `scid` are added if absent. */
  parameters: Record<string, unknown>;
  versionTime: string;
  signers: string[];
}

/** Creates a did:vh DID log. Like VH-Log generation, it does not validate its input. */
export function createDid(input: CreateDidInput): { log: string; did: string; scid: string; versionId: string } {
  const result = createLog(
    { state: input.document, parameters: input.parameters, versionTime: input.versionTime, signers: input.signers },
    "method",
    DID_VH_METHOD,
  );
  return { log: result.log, did: DID_PREFIX + result.scid, scid: result.scid, versionId: result.versionId };
}

export interface UpdateDidInput {
  log: string;
  document: Record<string, unknown>;
  parameters?: Record<string, unknown>;
  versionTime: string;
  signers: string[];
}

/** Appends an entry to a did:vh DID log. Deactivate with `parameters: {deactivated: true}`. */
export function updateDid(input: UpdateDidInput): { log: string; versionId: string } {
  const update: UpdateInput = {
    log: input.log,
    state: input.document,
    parameters: input.parameters,
    versionTime: input.versionTime,
    signers: input.signers,
  };
  return updateLog(update);
}

// ---------------------------------------------------------------- shared URL checks

/** Unicode White_Space (profile §3). */
const WHITESPACE = new RegExp("^[\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]$", "u");

/** Percent-decodes `s` to a UTF-8 string, or null if an escape or the UTF-8 is malformed. */
export function percentDecode(s: string): string | null {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "%") {
      const hex = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else {
      // Unescaped characters are taken whole (by code point), not per UTF-16 unit.
      const ch = String.fromCodePoint(s.codePointAt(i)!);
      if (!ch.isWellFormed()) return null;
      bytes.push(...new TextEncoder().encode(ch));
      i += ch.length - 1;
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
  } catch {
    return null;
  }
}

const isOctet = (s: string) => /^(0|[1-9][0-9]{0,2})$/.test(s) && Number(s) <= 255;

function isLoopbackHost(host: string): boolean {
  if (host === "localhost" || host === "[::1]") return true;
  const parts = host.split(".");
  return parts.length === 4 && parts.every(isOctet) && parts[0] === "127";
}

function isDomainName(host: string): boolean {
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  if (name.length === 0 || name.length > 253) return false;
  const labels = name.split(".");
  if (/^[0-9]+$/.test(labels.at(-1)!)) return false; // an IPv4 literal, or ends in a number
  return labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
}

/** Splits `scheme:rest` (profile §3 steps 1–2); null if `value` is not printable ASCII with a scheme. */
function splitScheme(value: unknown): { scheme: string; rest: string } | null {
  if (typeof value !== "string" || !/^[\x21-\x7e]+$/.test(value)) return null;
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/s.exec(value);
  return m ? { scheme: m[1].toLowerCase(), rest: m[2] } : null;
}

/** Checks an `http(s)` authority (profile §3); returns the lowercased host, or null. */
function checkAuthority(authority: string, scheme: "https" | "http"): string | null {
  if (authority.includes("@")) return null;
  let host: string;
  let port: string | null = null;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close === -1) return null;
    host = authority.slice(0, close + 1);
    const after = authority.slice(close + 1);
    if (after !== "") {
      if (!after.startsWith(":")) return null;
      port = after.slice(1);
    }
  } else {
    const colon = authority.indexOf(":");
    host = colon === -1 ? authority : authority.slice(0, colon);
    if (colon !== -1) port = authority.slice(colon + 1);
  }
  host = host.toLowerCase();
  if (port !== null && !(/^[0-9]{1,5}$/.test(port) && Number(port) <= 65535)) return null;
  if (scheme === "http") return isLoopbackHost(host) ? host : null;
  return !host.startsWith("[") && isDomainName(host) ? host : null;
}

/**
 * Checks the segments of a path that starts with `/` (profile §3). Each is
 * percent-decoded and must not be `.` or `..` or contain `/`, `\` or NUL.
 * With `strict` (the `src` DID URL parameter), it must also be non-empty and
 * not start or end with whitespace.
 */
function checkSegments(path: string, strict: boolean): boolean {
  for (const raw of path.slice(1).split("/")) {
    const segment = percentDecode(raw);
    if (segment === null || segment === "." || segment === ".." || /[/\\\0]/.test(segment)) return false;
    if (strict) {
      if (segment === "") return false;
      const chars = [...segment];
      if (WHITESPACE.test(chars[0]) || WHITESPACE.test(chars.at(-1)!)) return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------- srcLog / srcWitness references

export type RefKind = "web" | "loopback" | "file" | "other";

/**
 * Validates a `srcLog` or `srcWitness` reference, which names a file
 * (profile §3.1), and returns its kind. Throws `invalidOptions`.
 */
export function checkRef(ref: unknown): RefKind {
  const invalid = (why: string) => new DidVhError("invalidOptions", `reference ${JSON.stringify(ref)}: ${why}`);
  const parts = splitScheme(ref);
  if (!parts) throw invalid("not a printable-ASCII absolute URL");
  const { scheme, rest } = parts;
  if (rest.includes("#")) throw invalid("must not have a fragment");

  if (scheme === "https" || scheme === "http") {
    if (!rest.startsWith("//")) throw invalid("missing authority");
    const end = rest.slice(2).search(/[/?]/);
    const authority = end === -1 ? rest.slice(2) : rest.slice(2, end + 2);
    const afterAuthority = end === -1 ? "" : rest.slice(end + 2);
    const q = afterAuthority.indexOf("?");
    const path = q === -1 ? afterAuthority : afterAuthority.slice(0, q);
    if (checkAuthority(authority, scheme) === null) {
      throw invalid(scheme === "http" ? "http is only allowed with a loopback host" : "invalid https host");
    }
    if (path === "") throw invalid("must have a path");
    if (!checkSegments(path, false)) throw invalid("invalid path segment");
    return scheme === "http" ? "loopback" : "web";
  }

  if (scheme === "file") {
    if (rest.includes("?")) throw invalid("must not have a query");
    let path: string;
    if (rest.startsWith("//")) {
      const slash = rest.indexOf("/", 2);
      if (slash === -1) throw invalid("file URL needs an absolute path");
      const host = rest.slice(2, slash).toLowerCase();
      if (host !== "" && host !== "localhost") throw invalid("file URL host must be empty or localhost");
      path = rest.slice(slash);
    } else {
      if (!rest.startsWith("/")) throw invalid("file URL needs an absolute path");
      path = rest;
    }
    if (!checkSegments(path, false)) throw invalid("invalid path segment");
    return "file";
  }

  if (rest === "") throw invalid("empty URL");
  return "other";
}

// ---------------------------------------------------------------- the src DID URL parameter

/**
 * Validates a (percent-decoded) `src` DID URL parameter and derives the
 * `srcLog` and `srcWitness` references from it (profile §3.2). Throws
 * `invalidDidUrl`.
 */
export function srcReferences(src: unknown): { srcLog: string; srcWitness: string } {
  const invalid = (why: string) => new DidVhError("invalidDidUrl", `src ${JSON.stringify(src)}: ${why}`);
  const parts = splitScheme(src);
  if (!parts) throw invalid("not a printable-ASCII absolute URL");
  const { scheme, rest } = parts;
  if (rest.includes("?") || rest.includes("#")) throw invalid("must not have a query or fragment");
  if (scheme === "http" || scheme === "file") throw invalid(`${scheme} is not allowed in a DID URL`);
  if (!rest.startsWith("//") || rest.length === 2 || rest[2] === "/") throw invalid("not a hierarchical URL with an authority");
  const base = rest.endsWith("/") ? rest.slice(0, -1) : rest;
  if (scheme === "https") {
    const slash = base.indexOf("/", 2);
    const authority = slash === -1 ? base.slice(2) : base.slice(2, slash);
    const path = slash === -1 ? "" : base.slice(slash);
    if (checkAuthority(authority, "https") === null) throw invalid("invalid https host");
    if (path !== "" && !checkSegments(path, true)) throw invalid("invalid path segment");
  }
  const location = `${scheme}:${base}`;
  return { srcLog: `${location}/did.jsonl`, srcWitness: `${location}/did-witness.json` };
}

// ---------------------------------------------------------------- DID URLs

export interface DidUrl {
  did: string;
  /** Resolution options from the query: srcLog and srcWitness (from src), versionId, versionTime, versionNumber. */
  options: DidResolutionOptions;
  fragment?: string;
}

const URL_PARAMETERS = ["src", "versionId", "versionTime", "versionNumber"];
const OPTION_ONLY = ["didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog"];

/**
 * Parses a did:vh DID URL as a dereferencer does (profile §4): `src` becomes
 * the `srcLog` and `srcWitness` options, and the version parameters become
 * the options of the same name. Throws `invalidDidUrl`.
 */
export function parseDidUrl(didUrl: unknown): DidUrl {
  const invalid = (why: string) => new DidVhError("invalidDidUrl", `${JSON.stringify(didUrl)}: ${why}`);
  if (typeof didUrl !== "string") throw invalid("not a string");
  const hash = didUrl.indexOf("#");
  const beforeFragment = hash === -1 ? didUrl : didUrl.slice(0, hash);
  const fragment = hash === -1 ? undefined : didUrl.slice(hash + 1);
  const q = beforeFragment.indexOf("?");
  const did = q === -1 ? beforeFragment : beforeFragment.slice(0, q);
  if (parseDid(did) === null) throw invalid("not a did:vh DID");
  const seen = new Set<string>();
  const options: DidResolutionOptions = {};
  if (q !== -1) {
    for (const pair of beforeFragment.slice(q + 1).split("&")) {
      const eq = pair.indexOf("=");
      if (eq === -1) throw invalid(`query parameter ${JSON.stringify(pair)} has no value`);
      const key = percentDecode(pair.slice(0, eq));
      const value = percentDecode(pair.slice(eq + 1));
      if (key === null || value === null) throw invalid("malformed percent-encoding");
      if (OPTION_ONLY.includes(key)) throw invalid(`${key} is a resolution option, not a DID URL parameter`);
      if (!URL_PARAMETERS.includes(key)) continue;
      if (seen.has(key)) throw invalid(`${key} given more than once`);
      seen.add(key);
      if (key === "src") {
        Object.assign(options, srcReferences(value));
      } else if (key === "versionNumber") {
        if (!/^[1-9][0-9]{0,15}$/.test(value)) throw invalid("versionNumber must be a positive integer");
        options.versionNumber = Number(value);
      } else {
        options[key as "versionId" | "versionTime"] = value;
      }
    }
  }
  return fragment === undefined ? { did, options } : { did, options, fragment };
}

// ---------------------------------------------------------------- resolve

export interface DidResolutionOptions {
  didLog?: string;
  didWitness?: unknown;
  srcLog?: string;
  srcWitness?: string;
  versionId?: string;
  versionTime?: string;
  versionNumber?: number;
  checkWatchers?: number | "all";
  extraWatchers?: string[];
  minCopies?: number;
  includeDidLog?: boolean;
  [other: string]: unknown;
}

export interface ResolverContext {
  /** ISO 8601 time used as the resolver's clock; defaults to the current time. */
  now?: string;
  /** True for a resolver that accepts requests from other systems (profile §5). */
  remote?: boolean;
}

export interface ProblemDetails {
  title: DidVhErrorCode;
  detail: string;
  /** The VH-Log error behind a did:vh error, where there is one. */
  vhLog?: ErrorReport;
}

export interface Warning {
  code: string;
  message: string;
  source?: string;
}

export interface DidDocumentMetadata {
  versionId: string;
  versionTime: string;
  created: string;
  updated: string;
  scid: string;
  deactivated: boolean;
  ttl: number;
  witness?: WitnessConfig;
  watchers: string[];
}

export interface DidResolutionSuccessMetadata {
  contentType: "application/did+json";
  warnings?: Warning[];
  didLog?: string;
  didWitness?: unknown[];
}

export type DidResolutionResult =
  | {
      didResolutionMetadata: DidResolutionSuccessMetadata;
      didDocument: Record<string, unknown> | null;
      didDocumentMetadata: DidDocumentMetadata;
    }
  | {
      didResolutionMetadata: { error: DidVhErrorCode; problemDetails: ProblemDetails };
      didDocument: null;
      didDocumentMetadata: Record<string, never>;
    };

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isPositiveInteger = (v: unknown) => typeof v === "number" && Number.isInteger(v) && v >= 1;

/** did:vh Resolution Options validation (profile §5, step 2). */
function validateOptions(options: unknown, remote: boolean): DidResolutionOptions {
  const invalid = (why: string) => new DidVhError("invalidOptions", why);
  if (!isObject(options)) throw invalid("resolution options must be an object");
  const o = options as DidResolutionOptions;
  if (("didLog" in o) === ("srcLog" in o)) throw invalid("exactly one of didLog and srcLog must be given");
  if ("didWitness" in o && "srcWitness" in o) throw invalid("at most one of didWitness and srcWitness may be given");
  if ("didLog" in o && typeof o.didLog !== "string") throw invalid("didLog must be a string");
  if ("didWitness" in o && !Array.isArray(o.didWitness)) throw invalid("didWitness must be an array");
  for (const key of ["srcLog", "srcWitness"] as const) {
    if (!(key in o)) continue;
    const kind = checkRef(o[key]);
    if (remote && (kind === "file" || kind === "loopback")) {
      throw invalid(`${key}: a resolver that serves other systems must not use local file or loopback references`);
    }
  }
  const selectors = ["versionId", "versionTime", "versionNumber"].filter((k) => k in o);
  if (selectors.length > 1) throw invalid("at most one of versionId, versionTime and versionNumber may be given");
  if ("versionId" in o && typeof o.versionId !== "string") throw invalid("versionId must be a string");
  if ("versionTime" in o && parseVersionTime(o.versionTime) === null) {
    throw invalid("versionTime must be a whole-second UTC ISO 8601 time");
  }
  if ("versionNumber" in o && !isPositiveInteger(o.versionNumber)) throw invalid("versionNumber must be a positive integer");
  if ("checkWatchers" in o) {
    const c = o.checkWatchers;
    if (c !== "all" && !(typeof c === "number" && Number.isInteger(c) && c >= 0)) {
      throw invalid('checkWatchers must be a non-negative integer or "all"');
    }
  }
  if ("extraWatchers" in o) {
    const w = o.extraWatchers;
    if (!Array.isArray(w) || !w.every((u) => typeof u === "string" && u.startsWith("https://") && isWatcherUrl(u))) {
      throw invalid("extraWatchers must be an array of https URLs");
    }
  }
  if ("minCopies" in o && !isPositiveInteger(o.minCopies)) throw invalid("minCopies must be a positive integer");
  if ("includeDidLog" in o && typeof o.includeDidLog !== "boolean") throw invalid("includeDidLog must be a boolean");
  return o;
}

const ERROR_MAP: Partial<Record<string, DidVhErrorCode>> = {
  "not-found": "notFound",
  "invalid-option": "invalidOptions",
  "fork-detected": "logForked",
  "min-copies-not-met": "insufficientCopies",
  "unsupported-log-version": "featureNotSupported",
};

function failure(error: DidVhError): DidResolutionResult {
  const problemDetails: ProblemDetails = { title: error.code, detail: error.message };
  if (error.vhLog) problemDetails.vhLog = error.vhLog;
  return { didResolutionMetadata: { error: error.code, problemDetails }, didDocument: null, didDocumentMetadata: {} };
}

const currentTime = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

/**
 * did:vh `resolve(did, resolutionOptions)` (profile §5). This resolver is
 * offline: it verifies a log passed in `didLog` (and `didWitness`), and
 * returns `featureNotSupported` when it would have to retrieve anything.
 */
export function resolveDid(did: string, resolutionOptions: unknown = {}, context: ResolverContext = {}): DidResolutionResult {
  try {
    const scid = parseDid(did);
    if (scid === null) throw new DidVhError("invalidDid", `${JSON.stringify(did)} is not a did:vh DID`);
    const options = validateOptions(resolutionOptions, context.remote ?? false);
    if ("srcLog" in options) throw new DidVhError("featureNotSupported", "this resolver does not retrieve srcLog references");
    if ((options.checkWatchers ?? 0) !== 0 || (options.extraWatchers?.length ?? 0) > 0) {
      throw new DidVhError("featureNotSupported", "this resolver does not retrieve copies from watchers");
    }
    const spec = didVhSpecialisation(scid);
    const now = context.now ?? currentTime();
    const log = options.didLog!;
    // Whether the log needs witnessing does not depend on the witness file. Without
    // one, the first entry that needs it fails, which cuts it from `entries`.
    const unwitnessed = verifyLog(log, undefined, parseVersionTime(now) ?? Date.now(), spec);
    const witnessed =
      unwitnessed.failure?.code === "witness-threshold-not-met" || unwitnessed.entries.some((e) => e.witnessRule !== null);
    if (witnessed && "srcWitness" in options) {
      throw new DidVhError("featureNotSupported", "this resolver does not retrieve srcWitness references");
    }
    const vhOptions: Record<string, unknown> = {};
    for (const key of ["versionId", "versionTime", "versionNumber", "minCopies"]) {
      if (key in options) vhOptions[key] = options[key];
    }
    const result = resolve({ log, witness: options.didWitness, now, options: vhOptions }, spec);
    if (!result.valid) {
      throw new DidVhError(ERROR_MAP[result.error.code] ?? "invalidDid", result.error.message, result.error);
    }
    const selected = ["versionId", "versionTime", "versionNumber"].some((k) => k in options);
    if (!selected && result.error?.code === "unsupported-log-version") {
      // Entries after the last valid one may change the document or its keys (profile §5).
      throw new DidVhError("featureNotSupported", result.error.message, result.error);
    }
    const m = result.metadata;
    // A deactivated DID's document is not returned; earlier versions still are (profile §5).
    // A deactivated DID's document is returned only for an explicit version selector (profile §5).
    const didDocumentMetadata: DidDocumentMetadata = {
      versionId: m.versionId,
      versionTime: m.versionTime,
      created: m.created,
      updated: m.updated,
      scid: m.scid,
      deactivated: m.deactivated,
      ttl: m.ttl,
      ...(m.witness ? { witness: m.witness } : {}),
      watchers: m.watchers,
    };
    const meta: DidResolutionSuccessMetadata = { contentType: "application/did+json" };
    if (m.warnings.length) meta.warnings = m.warnings;
    if (options.includeDidLog === true) {
      const lines = parseLogLines(log);
      const valid = result.firstInvalidVersion === null ? lines.length : result.firstInvalidVersion - 1;
      meta.didLog = lines.slice(0, valid).map((l) => l + "\n").join("");
      if (witnessed) meta.didWitness = Array.isArray(options.didWitness) ? options.didWitness : [];
    }
    return {
      didResolutionMetadata: meta,
      didDocument: m.deactivated && !selected ? null : result.state,
      didDocumentMetadata,
    };
  } catch (e) {
    if (e instanceof DidVhError) return failure(e);
    throw e;
  }
}

export { SCID_PLACEHOLDER };
