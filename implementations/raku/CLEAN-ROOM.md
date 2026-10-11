# Clean-room record

This is a fresh independent implementation written in this conversation. Its
implementation directory was empty when work began. No implementation source
in another language, implementation diff/history, vector generator, or another
clean-room's findings was inspected. The harness was read as explicitly allowed;
its imports were not followed. Running a TypeScript driver for black-box cross
checks did not expose its implementation source.

Permitted inputs used:

- `docs/profile.md`, `docs/interop-protocol.md`, `docs/spec-notes.md`.
- `harness/run.ts`, the shared `vectors/` JSON files, and implementation registry.
- Pinned upstream `VH-Log/spec/specification.md` at `f2f9fda`, supplied under
  `/tmp/vhlog-spec/VH-Log/spec/`.
- Rakudo's core NativeCall and Unicode behavior, libsodium's published API,
  C++17 `std::to_chars`, and Rakudo release build metadata.

No subagents were spawned. Only this directory was changed; no commits or pushes
were made.

## Implementation choices

- JSON numbers become `Num` immediately, including integer tokens. The native
  helper asks `to_chars` for shortest scientific digits rather than unrestricted
  layout: unrestricted layout can choose an exact large integer with too many
  significant digits. Raku then applies ECMAScript's decimal/exponent thresholds.
- Ordinary Raku NFG strings can normalize decomposed text and presentation
  forms. JSON parsing, raw I/O and UTF-16 ordering therefore use `utf8-c8`,
  with a scalar-validating UTF-8 decoder. Escapes and emitted JSON strings are
  assembled as code-point arrays and encoded without normalization. Native
  callers should use `parse-json` on losslessly decoded bytes for exact JCS.
- The parser is recursive descent rather than a Raku grammar because it must
  operate on Unicode scalar values rather than NFG grapheme matches. Timestamp,
  number and encoding syntax use Raku regexes.
- libsodium NativeCall implements SHA-256/SHA-512 and Ed25519. No subprocess or
  external implementation handles VH-Log. SHA-512 is a library primitive;
  profile log hashes remain exclusively SHA-256.
- Parameters are snapshotted after each valid entry; copying the mutable hash is
  necessary so historical selections and partial witness failure return prior
  values. Key arrays and witness objects are never mutated internally.
- Whole-second timestamps use integer proleptic Gregorian arithmetic, without
  depending on platform date/time limits or string comparisons.
- Copies with matching overlapping ids follow the spec's trust rule. A longer
  matching copy is verified using the reference's already verified prefix;
  prefix witness checks are reused, and its additional entries are checked.
- The library performs no networking. Request-provided copies cover watcher
  comparison; unsupported network retrieval options fail `invalid-option`.

## Vector-forced readings and ambiguities

- Malformed JSON, blank interior lines, non-finite numbers and lone surrogates
  invalidate their own version while preserving prior entries. An empty log's
  error version is JSON null. Invalid base58 in an entry id is
  `invalid-version-id`, whereas a decodable hash with the wrong codec is
  `invalid-hash-algorithm`.
- Copy warnings are `copy-behind`, `copy-invalid`, and `copy-unavailable`.
  A primary that failed full verification is discarded and reported invalid
  even if its ids match a subsequently verified reference. Other matching copies
  need no further full verification, including the tampered-copy fixture.
- Fork errors report both `error.version` and `error.fork.version`; errors
  unrelated to a specific entry include `version: null`.
- A retained version later than every retrieved entry produces
  `retained-version-not-found`, following the upstream permitted warning path.
- Witness configuration in result metadata is that at the last valid entry,
  including when witnessing reduces the valid prefix. Replacing/disabling an
  active list uses the old list for that entry. The first enabled list applies
  immediately. All these readings come directly from the profile and vectors.
- Unknown parameters are ignored, but null values are rejected under the
  upstream general prohibition on null parameter values; unknown-null behavior
  is not separately exercised by shared vectors.
- When no copy fully verifies, the primary's valid prefix is returned under the
  profile partial-validity policy; an explicit `minCopies > 1` still fails.
  This combination is not separately covered by shared vectors.
- Local tests exercise lossless decomposed Unicode and invalid UTF-8, which
  shared vectors do not cover. Native Raku strings may already have normalized
  before they reach this library; the documented lossless parser boundary is
  required when preserving externally supplied bytes.

## Verification and reproducibility

On macOS arm64: Rakudo 2026.09, libsodium 1.0.22, Apple Clang C++17.

- `sh scripts/test.sh`: 23 library checks passed.
- `node harness/run.ts --impl raku`: all 257 checks passed.
- `node harness/run.ts --impl typescript --impl raku --suite cross`: both
  implementations passed 12 cross checks each; all 60 checks including
  generation passed.

Linux setup pins Rakudo 2026.09 and libsodium 1.0.20 source archives with SHA-256
checksums. Rakudo's release metadata pins its NQP/MoarVM revisions. The host
compiler and operating-system packages are not pinned. This Linux bootstrap has
not been executed in this macOS environment; no Linux execution is claimed.
