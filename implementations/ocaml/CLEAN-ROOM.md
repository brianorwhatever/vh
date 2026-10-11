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
