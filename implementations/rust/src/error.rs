//! Error codes and error values (profile §6).

use serde::Serialize;
use std::fmt;

/// The failure codes defined by the interop profile (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    InvalidLog,
    InvalidEntry,
    InvalidParameter,
    UnsupportedLogVersion,
    PrerotationViolation,
    InvalidProof,
    UnauthorizedKey,
    InvalidVersionId,
    InvalidHashAlgorithm,
    EntryHashMismatch,
    InvalidVersionTime,
    FutureVersionTime,
    ScidMismatch,
    EntryAfterDeactivation,
    WitnessThresholdNotMet,
    InvalidWitnessFile,
    ForkDetected,
    MinCopiesNotMet,
    NotFound,
    InvalidOption,
}

impl ErrorCode {
    /// The code as it appears on the wire, e.g. `"entry-hash-mismatch"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidLog => "invalid-log",
            ErrorCode::InvalidEntry => "invalid-entry",
            ErrorCode::InvalidParameter => "invalid-parameter",
            ErrorCode::UnsupportedLogVersion => "unsupported-log-version",
            ErrorCode::PrerotationViolation => "prerotation-violation",
            ErrorCode::InvalidProof => "invalid-proof",
            ErrorCode::UnauthorizedKey => "unauthorized-key",
            ErrorCode::InvalidVersionId => "invalid-version-id",
            ErrorCode::InvalidHashAlgorithm => "invalid-hash-algorithm",
            ErrorCode::EntryHashMismatch => "entry-hash-mismatch",
            ErrorCode::InvalidVersionTime => "invalid-version-time",
            ErrorCode::FutureVersionTime => "future-version-time",
            ErrorCode::ScidMismatch => "scid-mismatch",
            ErrorCode::EntryAfterDeactivation => "entry-after-deactivation",
            ErrorCode::WitnessThresholdNotMet => "witness-threshold-not-met",
            ErrorCode::InvalidWitnessFile => "invalid-witness-file",
            ErrorCode::ForkDetected => "fork-detected",
            ErrorCode::MinCopiesNotMet => "min-copies-not-met",
            ErrorCode::NotFound => "not-found",
            ErrorCode::InvalidOption => "invalid-option",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One copy involved in a detected fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkCopy {
    pub source: String,
    pub version_id: String,
}

/// Where two copies (or a retained `versionId`) diverge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForkReport {
    pub version: u64,
    pub copies: Vec<ForkCopy>,
}

/// A verification or resolution failure. Serialises as the protocol's error report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VhLogError {
    pub code: ErrorCode,
    /// Version number of the entry that failed, where there is one.
    pub version: Option<u64>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkReport>,
}

impl VhLogError {
    pub fn new(code: ErrorCode, message: impl Into<String>, version: Option<u64>) -> Self {
        VhLogError {
            code,
            version,
            message: message.into(),
            fork: None,
        }
    }

    pub(crate) fn at(code: ErrorCode, version: u64, message: impl Into<String>) -> Self {
        Self::new(code, message, Some(version))
    }
}

impl fmt::Display for VhLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            Some(v) => write!(f, "{} at version {}: {}", self.code, v, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for VhLogError {}

/// Errors from the Log Controller (generation) functions and key handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// A seed was not 32 bytes of hex.
    InvalidSeed(String),
    /// `update` was given a log with no lines.
    EmptyLog,
    /// The last line of the log could not be used as a predecessor.
    InvalidLastLine(String),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateError::InvalidSeed(why) => write!(f, "invalid Ed25519 seed: {why}"),
            GenerateError::EmptyLog => f.write_str("cannot update an empty log"),
            GenerateError::InvalidLastLine(why) => write!(f, "invalid last log line: {why}"),
        }
    }
}

impl std::error::Error for GenerateError {}
