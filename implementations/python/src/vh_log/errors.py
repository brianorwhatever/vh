"""Error codes from the interop profile (profile section 6) and the library exception."""

from __future__ import annotations

from enum import StrEnum
from typing import NotRequired, TypedDict


class ErrorCode(StrEnum):
    """Every failure is reported with exactly one of these codes."""

    INVALID_LOG = "invalid-log"
    INVALID_ENTRY = "invalid-entry"
    INVALID_PARAMETER = "invalid-parameter"
    UNSUPPORTED_LOG_VERSION = "unsupported-log-version"
    PREROTATION_VIOLATION = "prerotation-violation"
    INVALID_PROOF = "invalid-proof"
    UNAUTHORIZED_KEY = "unauthorized-key"
    INVALID_VERSION_ID = "invalid-version-id"
    INVALID_HASH_ALGORITHM = "invalid-hash-algorithm"
    ENTRY_HASH_MISMATCH = "entry-hash-mismatch"
    INVALID_VERSION_TIME = "invalid-version-time"
    FUTURE_VERSION_TIME = "future-version-time"
    SCID_MISMATCH = "scid-mismatch"
    ENTRY_AFTER_DEACTIVATION = "entry-after-deactivation"
    WITNESS_THRESHOLD_NOT_MET = "witness-threshold-not-met"
    INVALID_WITNESS_FILE = "invalid-witness-file"
    FORK_DETECTED = "fork-detected"
    MIN_COPIES_NOT_MET = "min-copies-not-met"
    NOT_FOUND = "not-found"
    INVALID_OPTION = "invalid-option"


class ForkCopy(TypedDict):
    source: str
    versionId: str


class ForkReport(TypedDict):
    version: int
    copies: list[ForkCopy]


class ErrorReport(TypedDict):
    """JSON shape of an error in a resolution result."""

    code: str
    #: Version number of the entry that failed, where there is one.
    version: int | None
    message: str
    fork: NotRequired[ForkReport]


class VHLogError(Exception):
    """A verification or resolution failure carrying a profile error code."""

    code: ErrorCode
    version: int | None
    fork: ForkReport | None

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        version: int | None = None,
        fork: ForkReport | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.version = version
        self.fork = fork

    def to_report(self) -> ErrorReport:
        report: ErrorReport = {"code": self.code.value, "version": self.version, "message": self.message}
        if self.fork is not None:
            report["fork"] = self.fork
        return report

    def __repr__(self) -> str:
        return f"VHLogError({self.code.value!r}, {self.message!r}, version={self.version!r})"
