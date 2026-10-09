export type ErrorCode =
  | "invalid-log"
  | "invalid-entry"
  | "invalid-parameter"
  | "unsupported-log-version"
  | "prerotation-violation"
  | "invalid-proof"
  | "unauthorized-key"
  | "invalid-version-id"
  | "invalid-hash-algorithm"
  | "entry-hash-mismatch"
  | "invalid-version-time"
  | "future-version-time"
  | "scid-mismatch"
  | "entry-after-deactivation"
  | "witness-threshold-not-met"
  | "invalid-witness-file"
  | "fork-detected"
  | "min-copies-not-met"
  | "not-found"
  | "invalid-option";

export interface ForkReport {
  version: number;
  copies: { source: string; versionId: string }[];
}

export interface ErrorReport {
  code: ErrorCode;
  /** Version number of the entry that failed, where there is one. */
  version: number | null;
  message: string;
  fork?: ForkReport;
}

export class VHLogError extends Error {
  readonly code: ErrorCode;
  readonly version: number | null;
  readonly fork?: ForkReport;

  constructor(code: ErrorCode, message: string, version: number | null = null, fork?: ForkReport) {
    super(message);
    this.code = code;
    this.version = version;
    this.fork = fork;
  }

  toReport(): ErrorReport {
    const report: ErrorReport = { code: this.code, version: this.version, message: this.message };
    if (this.fork) report.fork = this.fork;
    return report;
  }
}
