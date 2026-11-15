// did:vh: the DID method specialisation of VH-Log (docs/didvh-profile.md).
//
// Everything about the log itself (hashing, proofs, witnesses, pre-rotation,
// version selection) is VH-Log, run with the DID_VH specialisation. This module
// adds the DID syntax, the `src` and DID URL rules, the resolution options, and
// the mapping to DID Resolution metadata and error codes.
import { VHLogError, type ErrorReport } from "./errors.ts";
import { createLog, SCID_PLACEHOLDER, updateLog, type UpdateInput } from "./log.ts";
import { resolve } from "./resolve.ts";
import { isWatcherUrl, parseVersionTime, type Specialisation, type WitnessConfig } from "./verify.ts";

export const DID_VH_METHOD = "did:vh:1.0";
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

// ---------------------------------------------------------------- src references

export type SrcKind = "web" | "loopback" | "file" | "other";

export interface SrcLocation {
  kind: SrcKind;
  /** Where the DID log is retrieved from. */
  didLog: string;
  /** Where the witness proofs file is retrieved from. */
  didWitness: string;
}

/** Unicode White_Space (profile §3.4). */
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
      bytes.push(...new TextEncoder().encode(s[i]));
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
  } catch {
    return null;
  }
}

function isPortOk(port: string): boolean {
  return /^[0-9]{1,5}$/.test(port) && Number(port) <= 65535;
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
  if (/^[0-9]+$/.test(labels.at(-1)!)) return false; // IPv4 literal (or ends in a number)
  return labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
}

function checkWebPath(path: string): boolean {
  if (path === "") return true;
  for (const raw of path.slice(1).split("/")) {
    const segment = percentDecode(raw);
    if (segment === null || segment === "" || segment === "." || segment === "..") return false;
    if (/[/\\\0]/.test(segment)) return false;
    const chars = [...segment];
    if (WHITESPACE.test(chars[0]) || WHITESPACE.test(chars.at(-1)!)) return false;
  }
  return true;
}

/** Strips one trailing `/`. */
const stripSlash = (path: string) => (path.endsWith("/") ? path.slice(0, -1) : path);

/**
 * Validates a `src` reference and works out where its files are (profile §3).
 * Throws `invalidOptions` for a value that is not a valid reference.
 */
export function locateSrc(src: unknown): SrcLocation {
  const invalid = (why: string) => new DidVhError("invalidOptions", `src ${JSON.stringify(src)}: ${why}`);
  if (typeof src !== "string" || !/^[\x21-\x7e]+$/.test(src)) throw invalid("must be printable ASCII");
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/s.exec(src);
  if (!m) throw invalid("not an absolute URL");
  const scheme = m[1].toLowerCase();
  const rest = m[2];
  if (rest.includes("?") || rest.includes("#")) throw invalid("must not have a query or fragment");
  const files = (base: string): [string, string] => [`${base}/did.jsonl`, `${base}/did-witness.json`];

  if (scheme === "https" || scheme === "http") {
    if (!rest.startsWith("//")) throw invalid("missing authority");
    const slash = rest.indexOf("/", 2);
    const authority = slash === -1 ? rest.slice(2) : rest.slice(2, slash);
    const path = stripSlash(slash === -1 ? "" : rest.slice(slash));
    if (authority.includes("@")) throw invalid("must not have user information");
    let host: string;
    let port: string | null = null;
    if (authority.startsWith("[")) {
      const close = authority.indexOf("]");
      if (close === -1) throw invalid("malformed IP literal");
      host = authority.slice(0, close + 1);
      const after = authority.slice(close + 1);
      if (after !== "") {
        if (!after.startsWith(":")) throw invalid("malformed authority");
        port = after.slice(1);
      }
    } else {
      const colon = authority.indexOf(":");
      host = colon === -1 ? authority : authority.slice(0, colon);
      if (colon !== -1) port = authority.slice(colon + 1);
    }
    host = host.toLowerCase();
    if (port !== null && !isPortOk(port)) throw invalid("malformed port");
    const loopback = scheme === "http";
    if (loopback ? !isLoopbackHost(host) : host.startsWith("[") || !isDomainName(host)) {
      throw invalid(loopback ? "http is only allowed with a loopback host" : "https host must be a domain name");
    }
    if (!checkWebPath(path)) throw invalid("invalid path segment");
    const base = `${scheme}://${rest.slice(2, slash === -1 ? undefined : slash)}`;
    const [didLog, didWitness] = path === "" ? [`${base}/.well-known/did.jsonl`, `${base}/.well-known/did-witness.json`] : files(base + path);
    return { kind: loopback ? "loopback" : "web", didLog, didWitness };
  }

  if (scheme === "file") {
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
    const [didLog, didWitness] = files(`file://${stripSlash(path)}`);
    return { kind: "file", didLog, didWitness };
  }

  if (!rest.startsWith("//") || rest.length === 2 || rest[2] === "/") throw invalid("not a hierarchical URL with an authority");
  const [didLog, didWitness] = files(`${scheme}:${stripSlash(rest)}`);
  return { kind: "other", didLog, didWitness };
}

// ---------------------------------------------------------------- DID URLs

export interface DidUrl {
  did: string;
  /** Resolution options taken from the query: src, versionId, versionTime, versionNumber. */
  options: DidResolutionOptions;
  fragment?: string;
}

const URL_OPTIONS = ["src", "versionId", "versionTime", "versionNumber"];

/**
 * Parses a did:vh DID URL as a dereferencer does (profile §4): the version
 * parameters and `src` become resolution options. Throws `invalidDidUrl`.
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
  const options: DidResolutionOptions = {};
  if (q !== -1) {
    for (const pair of beforeFragment.slice(q + 1).split("&")) {
      const eq = pair.indexOf("=");
      if (eq === -1) throw invalid(`query parameter ${JSON.stringify(pair)} has no value`);
      const key = percentDecode(pair.slice(0, eq));
      const value = percentDecode(pair.slice(eq + 1));
      if (key === null || value === null) throw invalid("malformed percent-encoding");
      if (key === "didLog" || key === "didWitness") throw invalid(`${key} is not allowed in a DID URL`);
      if (!URL_OPTIONS.includes(key)) continue;
      if (key in options) throw invalid(`${key} given more than once`);
      if (key === "src") {
        let location: SrcLocation;
        try {
          location = locateSrc(value);
        } catch {
          throw invalid("src is not a valid reference");
        }
        if (location.kind === "file" || location.kind === "loopback") {
          throw invalid("src in a DID URL must not be a local directory or loopback reference");
        }
        options.src = value;
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
  src?: string;
  versionId?: string;
  versionTime?: string;
  versionNumber?: number;
  checkWatchers?: boolean;
  extraWatchers?: string[];
  minCopies?: number;
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
  ttl: string;
  witness?: { threshold: string; witnesses: { id: string }[] };
  watchers: string[];
}

export type DidResolutionResult =
  | {
      didResolutionMetadata: { contentType: "application/did+json"; warnings?: Warning[] };
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

/** did:vh Resolution Options validation (profile §5). */
function validateOptions(options: unknown, remote: boolean): DidResolutionOptions {
  const invalid = (why: string) => new DidVhError("invalidOptions", why);
  if (!isObject(options)) throw invalid("resolution options must be an object");
  const o = options as DidResolutionOptions;
  if (("didLog" in o) === ("src" in o)) throw invalid("exactly one of didLog and src must be given");
  if ("didLog" in o && typeof o.didLog !== "string") throw invalid("didLog must be a string");
  if ("didWitness" in o) {
    if (!("didLog" in o)) throw invalid("didWitness may only be given with didLog");
    if (!Array.isArray(o.didWitness)) throw invalid("didWitness must be an array");
  }
  const selectors = ["versionId", "versionTime", "versionNumber"].filter((k) => k in o);
  if (selectors.length > 1) throw invalid("at most one of versionId, versionTime and versionNumber may be given");
  if ("versionId" in o && typeof o.versionId !== "string") throw invalid("versionId must be a string");
  if ("versionTime" in o && parseVersionTime(o.versionTime) === null) {
    throw invalid("versionTime must be a whole-second UTC ISO 8601 time");
  }
  if ("versionNumber" in o && !isPositiveInteger(o.versionNumber)) throw invalid("versionNumber must be a positive integer");
  if ("minCopies" in o && !isPositiveInteger(o.minCopies)) throw invalid("minCopies must be a positive integer");
  if ("checkWatchers" in o && typeof o.checkWatchers !== "boolean") throw invalid("checkWatchers must be a boolean");
  if ("extraWatchers" in o) {
    const w = o.extraWatchers;
    if (!Array.isArray(w) || !w.every((u) => typeof u === "string" && u.startsWith("https://") && isWatcherUrl(u))) {
      throw invalid("extraWatchers must be an array of https URLs");
    }
  }
  if ("src" in o) {
    const { kind } = locateSrc(o.src);
    if (remote && (kind === "file" || kind === "loopback")) {
      throw invalid("a resolver that serves other systems must not use local directory or loopback references");
    }
  }
  return o;
}

const ERROR_MAP: Partial<Record<string, DidVhErrorCode>> = {
  "not-found": "notFound",
  "invalid-option": "invalidOptions",
  "fork-detected": "logForked",
  "min-copies-not-met": "insufficientCopies",
};

function failure(error: DidVhError): DidResolutionResult {
  const problemDetails: ProblemDetails = { title: error.code, detail: error.message };
  if (error.vhLog) problemDetails.vhLog = error.vhLog;
  return { didResolutionMetadata: { error: error.code, problemDetails }, didDocument: null, didDocumentMetadata: {} };
}

/** Converts the VH-Log `witness` parameter to DID metadata form (threshold as a string). */
const witnessMetadata = (w: WitnessConfig) => ({ threshold: String(w.threshold), witnesses: w.witnesses });

/**
 * did:vh `resolve(did, resolutionOptions)` (profile §5). This resolver is
 * offline: it verifies a log passed in `didLog`/`didWitness`, and returns
 * `featureNotSupported` for `src`, `checkWatchers` and `extraWatchers`.
 */
export function resolveDid(did: string, resolutionOptions: unknown = {}, context: ResolverContext = {}): DidResolutionResult {
  try {
    const scid = parseDid(did);
    if (scid === null) throw new DidVhError("invalidDid", `${JSON.stringify(did)} is not a did:vh DID`);
    const options = validateOptions(resolutionOptions, context.remote ?? false);
    if ("src" in options) throw new DidVhError("featureNotSupported", "this resolver does not retrieve from src references");
    if (options.checkWatchers === true || (options.extraWatchers?.length ?? 0) > 0) {
      throw new DidVhError("featureNotSupported", "this resolver does not retrieve copies from watchers");
    }
    const vhOptions: Record<string, unknown> = {};
    for (const key of ["versionId", "versionTime", "versionNumber", "minCopies"]) {
      if (key in options) vhOptions[key] = options[key];
    }
    const result = resolve(
      {
        log: options.didLog!,
        witness: options.didWitness,
        now: context.now ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        options: vhOptions,
      },
      didVhSpecialisation(scid),
    );
    if (!result.valid) {
      const code = ERROR_MAP[result.error.code] ?? "invalidDid";
      throw new DidVhError(code, result.error.message, result.error);
    }
    const m = result.metadata;
    // A deactivated DID's document is not returned; earlier versions still are (profile §5).
    const isLast = m.versionTime === m.updated;
    const didDocumentMetadata: DidDocumentMetadata = {
      versionId: m.versionId,
      versionTime: m.versionTime,
      created: m.created,
      updated: m.updated,
      scid: m.scid,
      deactivated: m.deactivated,
      ttl: String(m.ttl),
      ...(m.witness ? { witness: witnessMetadata(m.witness) } : {}),
      watchers: m.watchers,
    };
    const warnings = m.warnings;
    return {
      didResolutionMetadata: { contentType: "application/did+json", ...(warnings.length ? { warnings } : {}) },
      didDocument: m.deactivated && isLast ? null : result.state,
      didDocumentMetadata,
    };
  } catch (e) {
    if (e instanceof DidVhError) return failure(e);
    throw e;
  }
}

export { SCID_PLACEHOLDER };
