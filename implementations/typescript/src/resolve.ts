import { VHLogError, type ErrorReport } from "./errors.ts";
import type { LogEntry } from "./log.ts";
import { parseVersionTime, verifyLog, type VerifiedEntry, type VerifiedLog, type WitnessConfig } from "./verify.ts";

export interface ResolveOptions {
  versionId?: string;
  versionTime?: string;
  versionNumber?: number;
  minCopies?: number;
}

export type CopyInput =
  | { source: string; log: string; witness?: unknown }
  | { source: string; unavailable: string };

export interface ResolveInput {
  log: string;
  witness?: unknown;
  /** ISO 8601 time used as the resolver's clock. */
  now: string;
  options?: ResolveOptions;
  copies?: CopyInput[];
  retainedVersionId?: string;
}

export type CopyStatus = "current" | "behind" | "invalid" | "unavailable";

export interface Warning {
  code: string;
  message: string;
  source?: string;
}

export interface ResolutionMetadata {
  versionId: string;
  versionTime: string;
  versionNumber: number;
  created: string;
  updated: string;
  scid: string;
  deactivated: boolean;
  ttl: number;
  witness: WitnessConfig | null;
  watchers: string[];
  updateKeys: string[];
  nextKeyHashes: string[];
  copies?: { source: string; versionId?: string; status: CopyStatus }[];
  warnings: Warning[];
}

export type ResolveResult =
  | {
      valid: true;
      state: Record<string, unknown>;
      metadata: ResolutionMetadata;
      firstInvalidVersion: number | null;
      error: ErrorReport | null;
    }
  | { valid: false; error: ErrorReport };

const OPTION_KEYS = ["versionId", "versionTime", "versionNumber", "minCopies"];
const PRIMARY = "primary";

function validateOptions(options: ResolveOptions): void {
  for (const key of Object.keys(options)) {
    if (!OPTION_KEYS.includes(key)) throw new VHLogError("invalid-option", `unsupported option ${key}`);
  }
  const selectors = ["versionId", "versionTime", "versionNumber"].filter((k) => k in options);
  if (selectors.length > 1) throw new VHLogError("invalid-option", "at most one version selector may be given");
  if ("versionId" in options && typeof options.versionId !== "string") {
    throw new VHLogError("invalid-option", "versionId must be a string");
  }
  if ("versionTime" in options && parseVersionTime(options.versionTime) === null) {
    throw new VHLogError("invalid-option", "versionTime must be a whole-second UTC ISO 8601 time");
  }
  for (const key of ["versionNumber", "minCopies"] as const) {
    if (key in options && (!Number.isInteger(options[key]) || options[key]! < 1)) {
      throw new VHLogError("invalid-option", `${key} must be a positive integer`);
    }
  }
}

function lineVersionId(lines: string[], index: number): string | null {
  try {
    const value = JSON.parse(lines[index]);
    return typeof value?.versionId === "string" ? value.versionId : null;
  } catch {
    return null;
  }
}

const isFullyValid = (v: VerifiedLog) => v.failure === null && v.entries.length === v.lines.length;

/**
 * Picks the target entry (Selecting a Version). A target at or after the first
 * invalid entry fails with that entry's error (profile §4).
 */
function selectEntry(verified: VerifiedLog, options: ResolveOptions): VerifiedEntry {
  const { entries, lines, failure } = verified;
  const invalid = () => new VHLogError(failure!.code, `requested version is invalid: ${failure!.message}`, failure!.version);
  if (options.versionId !== undefined) {
    const found = entries.find((e) => e.entry.versionId === options.versionId);
    if (found) return found;
    for (let i = entries.length; i < lines.length; i++) {
      if (lineVersionId(lines, i) === options.versionId) throw invalid();
    }
    throw new VHLogError("not-found", `no entry with versionId ${options.versionId}`);
  }
  if (options.versionNumber !== undefined) {
    if (options.versionNumber <= entries.length) return entries[options.versionNumber - 1];
    if (options.versionNumber <= lines.length) throw invalid();
    throw new VHLogError("not-found", `no entry with version number ${options.versionNumber}`);
  }
  if (options.versionTime !== undefined) {
    const time = parseVersionTime(options.versionTime)!;
    if (failure && entries.length < lines.length) {
      try {
        const firstInvalidTime = parseVersionTime(JSON.parse(lines[entries.length])?.versionTime);
        if (firstInvalidTime !== null && firstInvalidTime <= time) throw invalid();
      } catch (e) {
        if (e instanceof VHLogError) throw e;
      }
    }
    const found = entries.findLast((e) => e.time <= time);
    if (!found) throw new VHLogError("not-found", `no entry active at ${options.versionTime}`);
    return found;
  }
  return entries.at(-1)!;
}

function buildResult(
  verified: VerifiedLog,
  options: ResolveOptions,
  warnings: Warning[],
  copies?: ResolutionMetadata["copies"],
): ResolveResult {
  const target = selectEntry(verified, options);
  const first = verified.entries[0];
  const last = verified.entries.at(-1)!;
  if (verified.failure) {
    warnings.push({
      code: "invalid-entries",
      message: `entries from version ${verified.failure.version} fail verification: ${verified.failure.message}`,
    });
  }
  const metadata: ResolutionMetadata = {
    versionId: target.entry.versionId,
    versionTime: target.entry.versionTime,
    versionNumber: target.versionNumber,
    created: first.entry.versionTime,
    updated: last.entry.versionTime,
    scid: first.parameters.scid,
    deactivated: last.parameters.deactivated,
    ttl: last.parameters.ttl,
    witness: last.parameters.witness,
    watchers: last.parameters.watchers,
    updateKeys: target.parameters.updateKeys,
    nextKeyHashes: target.parameters.nextKeyHashes,
    warnings,
  };
  if (copies) metadata.copies = copies;
  return {
    valid: true,
    state: (target.entry as LogEntry).state,
    metadata,
    firstInvalidVersion: verified.failure ? verified.entries.length + 1 : null,
    error: verified.failure,
  };
}

function checkRetained(reference: VerifiedLog, referenceSource: string, retained: string, warnings: Warning[]): void {
  const m = /^([1-9][0-9]*)-/.exec(retained);
  if (!m) throw new VHLogError("invalid-option", "retainedVersionId is not a versionId");
  const n = Number(m[1]);
  if (reference.entries.length < n) {
    warnings.push({
      code: "retained-version-not-found",
      message: `the log has ${reference.entries.length} valid entries, fewer than retained version ${n}`,
    });
    return;
  }
  const versionId = reference.entries[n - 1].entry.versionId;
  if (versionId !== retained) {
    throw new VHLogError("fork-detected", `retained versionId differs at version ${n}`, n, {
      version: n,
      copies: [
        { source: "retained", versionId: retained },
        { source: referenceSource, versionId },
      ],
    });
  }
}

/** First version number at which two logs' versionIds differ. */
function divergence(a: string[], b: string[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (lineVersionId(a, i) !== lineVersionId(b, i)) return i + 1;
  return n + 1;
}

/** Comparing Copies of a Log, with copies supplied in the request instead of fetched. */
function resolveCopies(input: ResolveInput, now: number, options: ResolveOptions): ResolveResult {
  const all: CopyInput[] = [{ source: PRIMARY, log: input.log, witness: input.witness }, ...(input.copies ?? [])];
  const warnings: Warning[] = [];
  const status = new Map<number, CopyStatus>();
  const verified = new Map<number, VerifiedLog>();
  const verify = (i: number) => {
    if (!verified.has(i)) {
      const c = all[i] as { log: string; witness?: unknown };
      verified.set(i, verifyLog(c.log, c.witness, now));
    }
    return verified.get(i)!;
  };
  const markInvalid = (i: number) => {
    status.set(i, "invalid");
    const f = verify(i).failure;
    warnings.push({
      code: "copy-invalid",
      source: all[i].source,
      message: `copy fails verification at version ${f?.version ?? "?"}: ${f?.message ?? ""}`,
    });
  };

  for (let i = 0; i < all.length; i++) {
    const c = all[i];
    if ("unavailable" in c) {
      status.set(i, "unavailable");
      warnings.push({ code: "copy-unavailable", source: c.source, message: c.unavailable });
    }
  }

  let ref = -1;
  for (let i = 0; i < all.length && ref === -1; i++) {
    if (status.has(i)) continue;
    if (isFullyValid(verify(i))) ref = i;
    else markInvalid(i);
  }
  if (ref === -1) {
    const primary = verify(0);
    const error = primary.failure ?? { code: "invalid-log" as const, version: null, message: "no copy verifies" };
    return { valid: false, error };
  }

  const matched = new Set<number>([ref]);
  for (let i = 0; i < all.length; i++) {
    if (status.has(i) || matched.has(i)) continue;
    const reference = verify(ref);
    const refLines = reference.lines;
    const copyLines = verify(i).lines;
    if (copyLines.length === 0) {
      markInvalid(i);
      continue;
    }
    let extends_ = false;
    let same = false;
    if (copyLines.length <= refLines.length) {
      same = lineVersionId(copyLines, copyLines.length - 1) === reference.entries[copyLines.length - 1].entry.versionId;
    } else {
      extends_ = lineVersionId(copyLines, refLines.length - 1) === reference.entries.at(-1)!.entry.versionId;
    }
    if (same) {
      matched.add(i);
    } else if (extends_) {
      if (isFullyValid(verify(i))) {
        matched.add(i);
        ref = i;
      } else {
        markInvalid(i);
      }
    } else if (!isFullyValid(verify(i))) {
      markInvalid(i);
    } else {
      const version = divergence(refLines, copyLines);
      throw new VHLogError("fork-detected", `copies diverge at version ${version}`, version, {
        version,
        copies: [all[ref].source, all[i].source].map((source, k) => ({
          source,
          versionId: lineVersionId(k === 0 ? refLines : copyLines, version - 1) ?? "",
        })),
      });
    }
  }

  const reference = verify(ref);
  if (input.retainedVersionId !== undefined) {
    checkRetained(reference, all[ref].source, input.retainedVersionId, warnings);
  }
  const copies = all.map((c, i) => {
    if (status.has(i)) {
      const s = status.get(i)!;
      return s === "unavailable" ? { source: c.source, status: s } : { source: c.source, versionId: lineVersionId(verify(i).lines, verify(i).lines.length - 1) ?? undefined, status: s };
    }
    const lines = verify(i).lines;
    const behind = reference.lines.length - lines.length;
    if (behind > 0) {
      warnings.push({ code: "copy-behind", source: c.source, message: `copy is ${behind} entries behind` });
    }
    return { source: c.source, versionId: lineVersionId(lines, lines.length - 1)!, status: (behind > 0 ? "behind" : "current") as CopyStatus };
  });
  const usable = copies.filter((c) => c.status === "current" || c.status === "behind").length;
  if (usable < (options.minCopies ?? 1)) {
    throw new VHLogError("min-copies-not-met", `${usable} matching copies, ${options.minCopies} required`);
  }
  return buildResult(reference, options, warnings, copies);
}

export function resolve(input: ResolveInput): ResolveResult {
  try {
    const now = parseVersionTime(input.now);
    if (now === null) throw new VHLogError("invalid-option", "now must be a whole-second UTC ISO 8601 time");
    const options = input.options ?? {};
    validateOptions(options);
    if (input.copies !== undefined || (options.minCopies ?? 1) > 1) {
      return resolveCopies(input, now, options);
    }
    const verified = verifyLog(input.log, input.witness, now);
    if (verified.entries.length === 0) return { valid: false, error: verified.failure! };
    const warnings: Warning[] = [];
    if (input.retainedVersionId !== undefined) checkRetained(verified, PRIMARY, input.retainedVersionId, warnings);
    return buildResult(verified, options, warnings);
  } catch (e) {
    if (e instanceof VHLogError) return { valid: false, error: e.toReport() };
    throw e;
  }
}
