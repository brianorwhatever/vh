package vhlog

import (
	"encoding/json"
	"fmt"
)

// ErrorCode is one of the error codes of the interop profile (§6).
type ErrorCode string

// Error codes reported by verification and resolution.
const (
	ErrInvalidLog             ErrorCode = "invalid-log"
	ErrInvalidEntry           ErrorCode = "invalid-entry"
	ErrInvalidParameter       ErrorCode = "invalid-parameter"
	ErrUnsupportedLogVersion  ErrorCode = "unsupported-log-version"
	ErrPrerotationViolation   ErrorCode = "prerotation-violation"
	ErrInvalidProof           ErrorCode = "invalid-proof"
	ErrUnauthorizedKey        ErrorCode = "unauthorized-key"
	ErrInvalidVersionID       ErrorCode = "invalid-version-id"
	ErrInvalidHashAlgorithm   ErrorCode = "invalid-hash-algorithm"
	ErrEntryHashMismatch      ErrorCode = "entry-hash-mismatch"
	ErrInvalidVersionTime     ErrorCode = "invalid-version-time"
	ErrFutureVersionTime      ErrorCode = "future-version-time"
	ErrSCIDMismatch           ErrorCode = "scid-mismatch"
	ErrEntryAfterDeactivation ErrorCode = "entry-after-deactivation"
	ErrWitnessThresholdNotMet ErrorCode = "witness-threshold-not-met"
	ErrInvalidWitnessFile     ErrorCode = "invalid-witness-file"
	ErrForkDetected           ErrorCode = "fork-detected"
	ErrMinCopiesNotMet        ErrorCode = "min-copies-not-met"
	ErrNotFound               ErrorCode = "not-found"
	ErrInvalidOption          ErrorCode = "invalid-option"
)

// ForkCopy names one side of a detected fork.
type ForkCopy struct {
	Source    string `json:"source"`
	VersionID string `json:"versionId"`
}

// ForkReport describes where two copies of a log (or a retained versionId)
// diverge.
type ForkReport struct {
	Version int        `json:"version"`
	Copies  []ForkCopy `json:"copies"`
}

// VHLogError is a verification or resolution failure.
type VHLogError struct {
	// Code is the profile error code.
	Code ErrorCode
	// Version is the version number of the entry that failed, or 0 if the
	// failure does not concern one entry.
	Version int
	// Message is a human-readable explanation.
	Message string
	// Fork is set for ErrForkDetected.
	Fork *ForkReport
}

func newError(code ErrorCode, version int, format string, args ...any) *VHLogError {
	return &VHLogError{Code: code, Version: version, Message: fmt.Sprintf(format, args...)}
}

// Error implements error.
func (e *VHLogError) Error() string {
	if e.Version > 0 {
		return fmt.Sprintf("%s (version %d): %s", e.Code, e.Version, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// MarshalJSON encodes the error as the protocol's error report:
// {"code", "version" (null if 0), "message", "fork"?}.
func (e *VHLogError) MarshalJSON() ([]byte, error) {
	type report struct {
		Code    ErrorCode   `json:"code"`
		Version *int        `json:"version"`
		Message string      `json:"message"`
		Fork    *ForkReport `json:"fork,omitempty"`
	}
	r := report{Code: e.Code, Message: e.Message, Fork: e.Fork}
	if e.Version > 0 {
		v := e.Version
		r.Version = &v
	}
	return json.Marshal(r)
}
