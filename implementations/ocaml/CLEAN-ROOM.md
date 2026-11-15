# Clean-room record

This directory was implemented from scratch by its own Codex clean room.
It does not wrap a VH-Log implementation in another language.

## Sources used

- `docs/profile.md`, `docs/interop-protocol.md` and `docs/spec-notes.md`.
- Pinned upstream specification Markdown under `/tmp/vhlog-spec/VH-Log/spec/`,
  at commit `f2f9fda`.
- Shared `vectors/primitives.json`, `vectors/resolution/**` and the outputs of
  `harness/run.ts`; the harness itself was read to understand the wire protocol
  and expected comparison rules.
- OpenSSL EVP Ed25519/SHA primitive interfaces, C++17 `std::to_chars`, OCaml's
  standard library/native FFI, RFC 8032 and RFC 8785.
- The registry-selected TypeScript process was run only as an opaque producer
  and resolver for the permitted cross suite.

No other implementation source, implementation history/diff, vector generator,
or another clean room's findings was read. No sub-agents were delegated. Ancestor
`AGENTS.md` paths were checked without reading unrelated implementation code;
none applied. All files authored here stay within `implementations/ocaml/`.

## Decisions from the specification and profile

- JSON parsing converts every number to finite IEEE binary64. It rejects invalid
  UTF-8, lone UTF-16 surrogate escapes, invalid JSON grammar and number overflow.
  Duplicate object keys use the final value. Object ordering uses decoded UTF-16
  code units, rather than UTF-8 bytes or Unicode scalar order.
- Binary64 digit selection is delegated to the C++ standard library's shortest
  scientific conversion; OCaml's requested output is formatted with RFC 8785's
  ECMAScript decimal/scientific boundaries (`1e-6` through values below `1e21`).
  SHA-256/SHA-512 and Ed25519 use maintained OpenSSL primitives only.
- Hashes cover canonical UTF-8 JSON. Proof configuration/document hashes are
  concatenated in that order. `proof` is omitted from signed/hash documents.
  Key commitments hash the multikey string's UTF-8 bytes.
- First-entry placeholder replacement and SCID verification operate on serialized
  JSON text. Generators do not reject semantically invalid controller parameters.
- Authorization uses prior update keys without pre-rotation and current explicit
  keys with pre-rotation. Witness lists follow the activation/rotation profile,
  distinct witness identities count once, and a later approval can witness an
  earlier entry under that earlier entry's applicable list.
- All structural/cryptographic/time checks precede witness checks. The resolver
  retains the valid prefix. It verifies every reference entry and every proof.
- Copy comparison trusts an already verified matching `versionId` prefix, as the
  specification requires. A longer matching copy verifies only its extension;
  differing copies are fully verified before being treated as forks.
- Witness identity validation permits only the profile's ASCII `did:key`
  Ed25519 form. Unicode NFC comparison consequently requires no transformation.
- Time calculation uses a proleptic Gregorian calendar including year zero and
  compares represented instants, accepting the profile's two UTC spellings.

## Readings forced by vectors

The initial independent implementation passed all primitive, controller and
external checks; eleven resolution discrepancies clarified these points:

- Blank interior lines and malformed/nonobject/I-JSON-unsafe lines invalidate the
  specific version, preserving earlier entries. An entirely empty log has an
  `invalid-log` error with no version. Only the final LF terminator is removed
  before reference-log parsing.
- A non-base58 entry-hash token is `invalid-version-id`; a decodable token with
  an unsupported/malformed multihash algorithm is `invalid-hash-algorithm`.
- `checkWatchers` is an unsupported option in this offline supplied-copy driver,
  despite being defined by the general upstream specification. `extraWatchers`
  is likewise not implemented. Supplied copies and `minCopies` are supported.
- A successfully verified primary that is extended by another copy is `behind`.
  A primary already rejected by full verification stays `invalid` even when its
  final `versionId` happens to match the chosen reference.

These corrections were inferred from allowed vectors and specification prose,
not from another implementation. The matching-prefix extension rule also has
an independent local test with a changed, unverified copy prefix.

## Choices and limitations not established by current vectors

- There is no HTTP publisher/retriever, key store or persistent resolver cache;
  the library operates on supplied bytes, timestamps, seed keys and copies.
- Metadata's witness configuration reflects the last valid entry, as the wire
  protocol requests. TTL/watchers and key commitments reflect the selected
  version's accumulated parameters. Exhaustive combinations of old selectors
  with changed TTL/watchers are not covered by this clean room's local tests.
- Witness file records and nonempty witness configurations require exactly the
  profile's declared properties. Extra witness-record/configuration properties
  are treated as malformed; acceptance of such properties is not established by
  the current vectors.
- No resource limits are imposed on JSON/log depth, entry count or request size.
  This library is intended to be embedded behind application-specific limits.
- Fixed-width base58 multihashes support SHA-256/SHA-512 primitives. General
  multicodec/hash algorithm registration is outside `vh-log-interop-0`.
- Linux setup is version/checksum pinned and shell syntax checked, but this work
  ran on macOS ARM64 rather than a Linux host. OpenSSL 3.6.5, OCaml 5.5.1 and
  Apple Clang 21.0.0 were used for all actual build/conformance checks.

## Verification

- `sh scripts/test.sh`: passed independent library tests, including RFC 8032
  public-key/signature and SHA-512 `abc` known answers, parser rejection,
  base58 round trips, proof tampering, typed generation/resolution, deactivation,
  partial validity, matching-copy extension, and fork rejection of older targets.
- `node harness/run.ts --impl ocaml`: 257/257 checks passed.
- `node harness/run.ts --impl typescript --impl ocaml --suite cross`: 60/60
  checks passed, including both implementations' generation and six scenarios
  resolved in both cross directions (and each implementation's self checks).

Source formatting uses ocamlformat 0.28.1 and clang-format. Those are development
tools only; the library and driver do not depend on them or on opam packages.

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
- Profile commit `68b1f52` (on `feat/didvh-reference`) was read only for its
  `docs/didvh-profile.md` and `vectors/didvh/did-url.json` changes: an
  unescaped character in a DID URL query is kept as a whole code point. Its
  TypeScript and generator changes were not read.
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

- §5 step 4, "A `srcWitness` is used only if the log needs witnessing":
  originally read syntactically (some line sets a non-empty `witness`), and
  for `didWitness` the same test on the valid lines. Superseded by the
  profile's definition: see "The log needs witnessing" below.
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
- OCaml specifics: `Vh_log.spec` is the specialisation record and
  `Vh_log.vh_log_spec` the default; `Didvh` (`src/didvh.ml`) is the did:vh
  module and the driver now dispatches through `Didvh.perform`. Percent-decoded
  bytes are checked with `String.is_valid_utf_8`.

### Verification (did:vh)

- `sh scripts/test.sh`: the library tests now also run every case in
  `vectors/didvh/{ref,src,did-url}.json` and `vectors/didvh/resolution/*.json`
  through `Didvh`, and resolve a freshly created DID.
- `node harness/run.ts --impl ocaml --impl typescript`: all suites green,
  including did:vh.

### The log needs witnessing (profile clarification)

`docs/didvh-profile.md` §5 step 4 now defines when "the log needs
witnessing": run the per-entry checks without a witness file, and the log
needs witnessing if the witness list that applies (`profile.md` §3) to any
entry before the first failing one is not `{}`. The same test decides when
`includeDidLog` returns `didWitness`. My earlier reading (some line sets a
non-empty `witness`) disagreed when the only witness list is in an invalid
entry; the vectors `src-witness-invalid-entry`,
`include-did-log-invalid-witness-entry` and `src-witness-later-entry` pin it.

Read for this change, and nothing else: the new §5 step 4 text,
`docs/profile.md` §3 and §4, `docs/didvh-profile.md` §1 (check 8), those
three vectors in `vectors/didvh/resolution/options.json`, and the harness
output. No other implementation, its history or diffs, or
`tools/generate-*.ts` was read.

Change: `Vh_log.check` takes `?witnesses` (default `true`); with `false` it
skips the witness pass and returns the entries that passed the per-entry
checks, each with the witness list that applies to it. A new
`Vh_log.needs_witnessing ?spec ~now log` runs it that way and asks whether
any of those lists is not `{}`. `Didvh` calls it with the did:vh spec (so
check 8 applies) for both step 4 and `didWitness`, so `didWitness` no longer
depends on witness verification either: an entry that passes the per-entry
checks but is not witnessed still counts. `sh scripts/test.sh` (which runs
the did:vh vectors, the three new ones included) passes.
