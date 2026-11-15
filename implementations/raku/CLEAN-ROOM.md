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


## did:vh (`didvh-interop-0`)

did:vh support was added later as a clean-room extension of this
implementation, by an agent that did not read any other implementation's
source (including `implementations/typescript` and its history or diffs),
`tools/generate-vectors.ts` or `tools/generate-didvh-vectors.ts`.

### Sources used

- `docs/didvh-profile.md`, the "did:vh operations" section of
  `docs/interop-protocol.md`, and `docs/profile.md`.
- The pinned DIF did:vh specification
  (`decentralized-identity/didvh@cc2eff6`) only where the profile links to it;
  every rule exercised here is restated by the profile.
- `vectors/didvh/**` and `harness/run.ts` (`didvh`, `didvhCross`,
  `compareDidResolution`) for the comparison rules.
- The TypeScript driver was run only as an opaque process in the harness's
  cross-resolution checks.

### Design

- The VH-Log verifier takes a *specialisation* (version parameter name,
  accepted values, optional version syntax, optional closed parameter set,
  optional per-entry state check). Plain VH-Log passes the default
  (`logVersion`, `vh-log:1.0`, no syntax, open set, no state check), so its
  behaviour is unchanged. With a syntax, a missing (entry 1) or malformed
  version parameter is `invalid-parameter`; a well-formed unaccepted value is
  `unsupported-log-version`. The closed-set check runs inside the parameter
  loop, before the version-value and pre-rotation checks. The state check
  runs on every entry after the SCID check and fails with `invalid-state`.
- The did:vh module builds on that: DID and DID URL parsing, `srcLog` /
  `srcWitness` reference checks, `src` derivation, create/update (VH-Log
  generation with `state` = the document and `method`, then `scid`, added when
  absent) and offline resolution.

### Interpretations of `docs/didvh-profile.md`

- §5 step 4, "A `srcWitness` is used only if the log needs witnessing,
  meaning some entry has an active witness list": this is decided *before*
  verification, so it is read syntactically: some line of `didLog` parses to an
  object whose `parameters.witness` is a non-empty object. (Any such entry
  makes some entry's applicable list non-empty.)
- §5 "`didWitness` is included only when the log needs witnessing": the same
  test, applied only to the lines of the valid entries.
- §5 step 6, "the log has an unsupported entry": VH-Log stops at the first
  failing entry, so this is detected only when that first failure is
  `unsupported-log-version` (an unsupported entry after an otherwise invalid
  one is never reached).
- §5 "`didLog` holds the original lines of the valid entries": lines are split
  as the VH-Log verifier splits them (on LF only, one final LF dropped), and
  the number of valid entries is `firstInvalidVersion - 1`, or all lines.
- §5 Deactivation, "if the resolved entry is the last valid entry": compared
  by version number.
- §5 `warnings`: the VH-Log warnings are passed through as they are, so
  `invalid-entries` also appears when an earlier version is selected
  explicitly (the vectors expect this).
- §4 step 3, "Each part MUST contain `=`": read literally, so an empty query
  (`did:vh:<SCID>?`) or an empty part (`a=1&&b=2`) is `invalidDidUrl`. Every
  part's name and value are decoded, including ignored ones, so a bad escape
  anywhere is `invalidDidUrl`.
- §4 step 6, `versionNumber` up to 16 digits becomes a JSON number via
  binary64, so values above 2^53 are rounded.
- §3.1 step 5, `file://localhost` (or `file://`) with no path is invalid: a
  path starting with `/` is required.
- §3.1 step 4, an IP literal needs its closing `]`; anything after it other
  than `:port` is invalid. An empty port (`host:`) is invalid (1–5 digits).
- §5 step 2, an option present with value `null` counts as present (so
  `"versionId": null` is `invalidOptions`).
- Raku specifics: `resolve-log` and `create-log` take `:%spec` and
  `:@defaults`; `vh-log-spec` is the default specialisation. Because Raku
  hashes have no key order, the closed-set check is a separate pass over every
  parameter (null check, then membership) before the existing per-parameter
  loop, which keeps its order for plain VH-Log. `VHLog::DidVh` is the did:vh
  module; DID URLs are split and percent-decoded on code points (`cps`) and
  rebuilt with `rawstr` (now exported from `VHLog::JSON`), so `utf8-c8` byte
  preservation is kept, and decoded bytes are validated by `cps`.

### Verification (did:vh)

- `sh scripts/test.sh`: 234 tests, including every case in
  `vectors/didvh/{ref,src,did-url}.json` and `vectors/didvh/resolution/*.json`
  through `VHLog::DidVh`, and resolution of a freshly created DID.
- `node harness/run.ts --impl raku --impl typescript`: all suites green,
  including did:vh.
