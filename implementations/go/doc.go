// Package vhlog implements VH-Log (Verifiable History Log, by Stephen Curran)
// following the vh-log-interop-0 profile of this repository
// (docs/profile.md).
//
// A VH-Log is a JSON Lines file of hash-chained, signed entries whose first
// entry fixes a self-certifying identifier (SCID). The package provides:
//
//   - Log Controller operations: CreateLog, UpdateLog and WitnessProof.
//   - Verification: VerifyLog runs every per-entry check and the witness
//     check, returning the valid prefix and the first failure.
//   - Resolution: Resolve selects a version (by versionId, versionTime or
//     versionNumber), applies the profile's partial-validity and
//     deactivation rules, compares watcher copies and checks a retained
//     versionId.
//   - Primitives: RFC 8785 canonicalisation (Canonicalize), base58btc,
//     SHA-256 multihashes, Ed25519 multikeys, and eddsa-jcs-2022 Data
//     Integrity proofs (CreateProof, VerifyProof).
//
// JSON values use a small model of their own (see ParseJSON): numbers are
// float64, objects are *Object (ordered, last duplicate key wins) and strings
// may carry lone surrogates. This is what RFC 8785 and the interop vectors
// require; encoding/json's generic decoding would silently change such input.
//
// Failures are reported as *VHLogError values carrying one of the ErrorCode
// constants. The package has no dependencies outside the standard library.
package vhlog
