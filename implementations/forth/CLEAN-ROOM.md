# Clean-room notes

This implementation was written from:

- `swcurran/VH-Log@f2f9fda`, `spec/specification.md` (the revision in `spec.lock.json`);
- `docs/profile.md` and `docs/interop-protocol.md`;
- the shared primitive, generation, resolution, and external vectors;
- the repository README, driver registry, CI workflow, and harness contract.

No other language's implementation source was read or translated. The shared
harness imports its existing canonicalizer as part of running tests; the Forth
driver neither imports nor invokes that implementation. Native dependencies are
general-purpose JSON, Unicode, numeric-formatting, and cryptographic libraries.

The profile resolves the choices needed to interoperate: exact error ordering,
previous-versus-current update keys, future-time tolerance, witness activation,
partial validity, and version-selection behavior. No new profile changes were
needed to pass the shared vectors.

Two details deserve explicit attention in independent implementations:

1. Witness verification runs only after the complete entry-validation pass
   succeeds. An invalid later entry preserves the preceding entry-valid prefix
   without running the witness pass. The `witness-checked-after-entries` vector
   pins this ordering; applying witness checks opportunistically changes the
   reported error and valid prefix.
2. Copy comparison deliberately trusts a matching boundary `versionId` without
   rechecking the matching prefix's contents. This includes a copy whose body
   has been altered behind unchanged version IDs. A longer matching copy must
   extend the already verified state; it must not replace that state with its
   unverified prefix. A separate driver regression exercises historical
   selection after extending such a copy.

These are observations about the specified interoperability behavior, not
additional validation rules introduced by this implementation.

## did:vh

did:vh support (`didvh.fs`, the hook in `specialisation.fs` and
`validation.fs`, the `method` default in `controller.fs`) was added under the
same rule: no other implementation, its git history or diffs,
`tools/generate-vectors.ts` or `tools/generate-didvh-vectors.ts` was read.
`native.cpp` is unchanged, so every did:vh rule (including percent-decoding
and UTF-8 validation) is in Forth. The sources were:

- `docs/didvh-profile.md` (`didvh-interop-0`), including the later §4 step 3
  note that an unescaped character is kept as a whole code point, the
  "did:vh operations" section of `docs/interop-protocol.md`, and
  `docs/profile.md`;
- the pinned DIF spec, `decentralized-identity/didvh@cc2eff6`, where the
  profile links to it;
- `vectors/didvh/**` and `harness/run.ts` (`didvh`, `didvhCross`,
  `compareDidResolution`).

Every did:vh vector passed on the first harness run. These are the places
where the profile left room, and where another implementation could differ
without a vector noticing:

| # | Profile passage | Choice made here |
| --- | --- | --- |
| 1 | §5 step 4: "the log needs witnessing, meaning some entry has an active witness list" | Decided syntactically, before verification: some line's `parameters.witness` is a non-empty object. For `includeDidLog`'s `didWitness` the same test runs on the valid entries only. |
| 2 | §4 step 3: "The query is split on `&`. Each part MUST contain `=`." | Applied literally: `did:vh:…?` (an empty query) and `?a=1&&b=2` (an empty part) are `invalidDidUrl`. |
| 3 | §4 step 3: an unescaped character "is kept as it is, as a whole code point" | Strings are UTF-8 bytes, so unescaped bytes are copied unchanged and the decoded result is checked as UTF-8 once. |
| 4 | §3.2 step 4: "one trailing `/` is removed" | Removed from the whole value before the authority and path checks, so `ipfs://x/` is valid and `https://h/a//` fails on its empty last segment. |
| 5 | §3.2 steps 3 and 5: other schemes need only "`//` and a non-empty authority" | For schemes other than `https`, the authority and path are not checked further. |
| 6 | §3.1 step 4: "A port is 1–5 digits" | An empty port (`https://h:/x`) is invalid. |
| 7 | §3.1 step 5: `file://localhost/<path>` | `file://localhost` with no `/` after the host is invalid. `file:///` is valid. |
| 8 | §5 step 2: the order of the option checks | Presence, `didLog`/`didWitness` types, references, selectors, then `checkWatchers`, `extraWatchers`, `minCopies`, `includeDidLog`. All give `invalidOptions`. |
| 9 | §5 Deactivation: "the resolved entry is the last valid entry" | Compared by version number: the resolved `versionNumber` equals the number of valid entries. |
| 10 | §2 Create: "`method` first, then `scid`" | The version parameter is now added before `scid` for VH-Log too (previously `scid` came first). Lines are compared as parsed JSON and hashes use JCS, so this changes no VH-Log result. |
| 11 | §1: a missing, malformed or non-string `method` is `invalid-parameter` | Implemented by the version syntax check; VH-Log's existing `logVersion` handling (a non-string value is `unsupported-log-version`) is unchanged. |
| 12 | §5: `didLog` "holds the original lines of the valid entries" | The lines as split on LF, byte for byte, each followed by LF. |
