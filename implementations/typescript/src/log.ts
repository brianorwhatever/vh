import { hashB58 } from "./hash.ts";
import { canonicalize } from "./jcs.ts";
import { createProof, type Proof, type ProofOptions } from "./proof.ts";

export const SCID_PLACEHOLDER = "{SCID}";
export const LOG_VERSION = "vh-log:1.0";

export interface LogEntry {
  versionId: string;
  versionTime: string;
  parameters: Record<string, unknown>;
  state: Record<string, unknown>;
  proof: Proof[];
}

type Unsigned = Record<string, unknown>;

function withoutProof(entry: Record<string, unknown>): Unsigned {
  const { proof: _, ...rest } = entry;
  return rest;
}

/** SCID of a preliminary entry (placeholders in place, `versionId` = `{SCID}`). */
export function computeScid(preliminary: Record<string, unknown>): string {
  return hashB58(canonicalize(withoutProof(preliminary)));
}

/** Entry hash: the entry without `proof`, with `versionId` set to its predecessor's. */
export function computeEntryHash(entry: Record<string, unknown>, previousVersionId: string): string {
  return hashB58(canonicalize({ ...withoutProof(entry), versionId: previousVersionId }));
}

/** Compact JSON with the field order from profile §5, plus the trailing newline. */
export function serializeEntry(entry: Record<string, unknown>): string {
  const ordered: Record<string, unknown> = {};
  for (const key of ["versionId", "versionTime", "parameters", "state", "proof"]) {
    if (key in entry) ordered[key] = entry[key];
  }
  for (const key of Object.keys(entry)) if (!(key in ordered)) ordered[key] = entry[key];
  return JSON.stringify(ordered) + "\n";
}

export function parseLogLines(log: string): string[] {
  const lines = log.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines;
}

export interface SealOptions {
  /** Proof options applied to every signer (test-vector use only). */
  proof?: ProofOptions;
  /** Override for the version number written into `versionId`. */
  versionNumber?: number | string;
  /** Override for the hash written into `versionId`. */
  entryHash?: string;
}

function sign(document: Unsigned, signers: string[], options: SealOptions): Proof[] {
  const created = (options.proof?.created ?? document.versionTime) as string;
  return signers.map((seed) => createProof(document, seed, { ...options.proof, created }));
}

/**
 * Turns a genesis body into a signed first entry: computes the SCID, replaces
 * the placeholder, computes the entry hash and signs. The body's own fields are
 * kept as given (no validation), so tests can seal deliberately invalid entries.
 */
export function sealGenesis(body: Unsigned, signers: string[], options: SealOptions = {}): { entry: LogEntry; scid: string } {
  const preliminary = { ...body, versionId: SCID_PLACEHOLDER };
  const scid = computeScid(preliminary);
  const replaced = JSON.parse(JSON.stringify(preliminary).replaceAll(SCID_PLACEHOLDER, scid)) as Unsigned;
  const hash = options.entryHash ?? computeEntryHash(replaced, scid);
  const document = { ...replaced, versionId: `${options.versionNumber ?? 1}-${hash}` };
  return { entry: { ...document, proof: sign(document, signers, options) } as unknown as LogEntry, scid };
}

/** Signs a later entry whose predecessor has `previousVersionId`. */
export function sealEntry(body: Unsigned, previousVersionId: string, signers: string[], options: SealOptions = {}): LogEntry {
  const previousNumber = Number.parseInt(previousVersionId.split("-")[0], 10);
  const hash = options.entryHash ?? computeEntryHash({ ...body, versionId: previousVersionId }, previousVersionId);
  const document = { ...body, versionId: `${options.versionNumber ?? previousNumber + 1}-${hash}` };
  return { ...document, proof: sign(document, signers, options) } as unknown as LogEntry;
}

export interface CreateInput {
  state: Record<string, unknown>;
  parameters: Record<string, unknown>;
  versionTime: string;
  signers: string[];
}

export function createLog(input: CreateInput): { log: string; scid: string; versionId: string } {
  const parameters = { ...input.parameters };
  if (!("logVersion" in parameters)) parameters.logVersion = LOG_VERSION;
  if (!("scid" in parameters)) parameters.scid = SCID_PLACEHOLDER;
  const { entry, scid } = sealGenesis(
    { versionId: SCID_PLACEHOLDER, versionTime: input.versionTime, parameters, state: input.state },
    input.signers,
  );
  return { log: serializeEntry(entry as unknown as Unsigned), scid, versionId: entry.versionId };
}

export interface UpdateInput {
  log: string;
  state: Record<string, unknown>;
  parameters?: Record<string, unknown>;
  versionTime: string;
  signers: string[];
}

export function updateLog(input: UpdateInput): { log: string; versionId: string } {
  const lines = parseLogLines(input.log);
  if (lines.length === 0) throw new Error("cannot update an empty log");
  const previous = JSON.parse(lines.at(-1)!) as LogEntry;
  const entry = sealEntry(
    {
      versionId: previous.versionId,
      versionTime: input.versionTime,
      parameters: input.parameters ?? {},
      state: input.state,
    },
    previous.versionId,
    input.signers,
  );
  const prefix = input.log.endsWith("\n") || input.log === "" ? input.log : input.log + "\n";
  return { log: prefix + serializeEntry(entry as unknown as Unsigned), versionId: entry.versionId };
}

/** A witness proof: eddsa-jcs-2022 over `{"versionId": …}` (profile §3). */
export function witnessProof(versionId: string, seedHex: string, created?: string): Proof {
  return createProof({ versionId }, seedHex, created === undefined ? {} : { created });
}
