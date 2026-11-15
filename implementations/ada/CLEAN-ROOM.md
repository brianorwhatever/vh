# Ada clean-room record

Written fresh in `implementations/ada/` without reading any other VH-Log
implementation, implementation history/diffs, vector generator, or another
clean room's findings. No code delegates VH-Log processing to another
language implementation. Only this implementation's directory was modified.

Inputs consulted:

- `docs/profile.md`, `docs/interop-protocol.md`, `docs/spec-notes.md`.
- Pinned specification markdown under `/tmp/vhlog-spec/VH-Log/spec/`, for
  `swcurran/VH-Log@f2f9fda`, especially `specification.md`.
- Published `vectors/primitives.json`, generation/resolution vectors and
  external cryptographic fixtures, and allowed `harness/run.ts`.
- Maintained Alire/GNAT toolchain and GNATformat distribution documentation,
  standard Ada UTF encoding facilities, C++17 number conversion, libsodium
  API/distribution information. GNATformat formatted only our Ada files.

The interop harness was run as a black box. Although its own imports refer to
TypeScript primitives, their source files were never inspected. A separate
number test uses ECMAScript `JSON.stringify` as the RFC 8785 numeric oracle,
without importing any repository implementation.

## Chosen readings

JCS numbers are IEEE binary64. Ada parses numbers as `Long_Float`, with a
compile-time 64-bit size requirement. C++ `std::to_chars` supplies shortest,
nearest round-tripping digits; our helper applies ECMAScript's fixed notation
range [-6, 20], exponent signs, trailing digit and negative-zero rules.
Object keys compare UTF-16 units, including supplementary surrogate pairs.
Our UTF-8 validator rejects overlong forms, invalid continuation bytes,
surrogate codepoints and values beyond U+10FFFF. U+FEFF inside strings remains
data. Duplicate JSON keys replace their previous values. Log splitting is LF
only; the final single trailing LF is a terminator rather than an empty entry.
Interior or repeated blank lines fail as entries. All 4-digit years, including
0000, use proleptic Gregorian date calculations.

Hashes are base58btc SHA-256 multihashes, with no multibase marker. Pre-rotation
hashes cover the multikey UTF-8 string. Ed25519 multikeys decode to the exact
`ed 01` codec and 32-byte key. SHA-512 is available as a primitive but is
rejected as a VH-Log 1.0 entry/SCID hash. A preliminary SCID primitive hashes
its input directly; callers supply the proof-free preliminary object.

Proof configuration and document hashes concatenate in configuration-first
order. The document's top-level `proof` is removed. Every entry proof must
verify and be authorized. Verification methods must have matching
`did:key:<mk>#<mk>` halves. Generators always use the entry versionTime as
created; standalone sign/witness omit it when absent and preserve an explicitly
supplied empty string. Non-pre-rotation key changes authorize the next entry;
pre-rotation changes authorize the current entry after commitments are checked.
While pre-rotation is active, explicit updateKeys and nextKeyHashes and at
least one committed update key are required.

Unknown parameters are ignored, including unknown null-valued parameters;
known null values fail. Watcher URLs use the profile's printable ASCII,
case-sensitive scheme and nonempty authority test. Witness ids must be
`did:key:` plus a valid Ed25519 multikey. Such ids are ASCII, so NFC does not
alter them; duplicate comparison is consequently byte-for-byte. Witness
configuration may include extra fields because the spec says witnesses must
include id and does not prohibit specialization fields.

Witness list replacement/removal applies after its changing entry; enabling
witnesses from {} applies immediately. Valid distinct witness approvals for
any current/later published version satisfy the earlier entry's own applicable
list. Unpublished approvals and unattributable/bad proofs are ignored. Only
witness file outer records (array, object, string versionId, array proof) are
schema-checked; unknown record fields are ignored. Empty proof arrays are
valid files but cannot satisfy thresholds.

Non-witness checks run in the profile's exact order. The published
`witness-checked-after-entries` vector forces a non-witness failure to be
returned before witness checks, even when an earlier entry lacks approvals.
When all non-witness checks pass, witness failures can invalidate an earlier
prefix. This resolves the possible tension between "only after every entry
has passed" and witness-based partial validity.

Partial validity preserves the verified prefix. Historical state and key
metadata use the selected entry; updated, deactivated, witness/watchers and ttl
use the last valid entry. Deactivation remains visible when selecting an earlier
version. With no selector, the last valid entry is returned with invalid-entries
when a later entry fails. Selecting a present invalid entry fails with that
entry's error; an absent selector target yields not-found.

Copy comparison tries primary first, then fully verified supplied copies.
Matching equal/shorter copies follow the specification's versionId shortcut;
the tampered-copy-same-version-ids vector deliberately pins that behavior.
An already rejected primary remains invalid when a replacement reference has
the same ids, as forced by `copies/invalid-primary`. Extending copies verify
only the new suffix using trusted reference configs and state; their cached
prefix is replaced with the reference's verified entries before resolution.
A divergent fully verified copy fails all selectors at the first differing
version. Retained mismatch also fails; retained version beyond the valid
reference warns. Current and behind statuses count toward minCopies.

## Limits and untested choices

All published vectors and black-box TypeScript/Ada cross checks pass. Native
tests additionally cover nested allocation lifetime, SHA-512, UTF-8 surrogate
rejection, BOM key ordering and tampered cached-prefix extension. A seeded
numeric oracle test checks 5,006 finite binary64 values; it is not an exhaustive
check over every possible double.

The Linux bootstrap pins GNAT native 16.1.0, Alire 2.1.1 and libsodium 1.0.22
with a verified source checksum. It has not been executed here; local execution
used native aarch64 macOS. No network watcher retrieval, caching persistence,
publication/governance policy or thread-safe allocator is supplied: these are
application responsibilities outside the harness profile. JSON allocation
scopes are single-task and require that borrowed values not escape their scope.
JSON construction APIs expose tagged records for flexible state; applications
must preserve well-formed JSON tags and use valid UTF-8 strings. Driver and
parser validate incoming JSON independently.

Malformed options with wrong types report invalid-option. Options supplied as
null are invalid rather than omitted. If copies are supplied and none passes
full verification, the primary valid prefix is kept internally but does not
count toward minCopies; thus min-copies-not-met wins if its minimum is unmet.
This simultaneous partial-copy/minCopies case is not covered by shared vectors.
Witness files that contain conflicting unknown versionIds are ignored under
the profile's unpublished-proof rule rather than rejected; no additional
unpublished-record consistency rule is imposed.


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
- Ada specifics: `VH_Log.Specialisation` is a record (no closures in
  access-to-subprogram values), so the state check is data-driven:
  `Check_State`, `State_Id_Prefix` (`did:vh:`) and `Expected_SCID` (the DID's
  SCID). The version syntax is an access-to-function (`Method_Syntax`). The
  closed-set check (with its null check) is a pass of its own before the
  existing parameter loop. `Did_VH` (`src/did_vh.ads`) is the did:vh package;
  the driver dispatches through `Did_VH.Dispatch`. DID URLs are split on the
  ASCII delimiter bytes, which never occur inside multi-byte UTF-8, so raw
  non-ASCII characters stay whole; decoded bytes are checked by a strict
  UTF-8 validator (no overlongs, surrogates or values above U+10FFFF).

### Verification (did:vh)

- `sh scripts/test.sh`: 233 native library checks, now including every case
  in `vectors/didvh/{ref,src,did-url}.json` and
  `vectors/didvh/resolution/*.json` through `Did_VH`, and resolution of a
  freshly created DID.
- `node harness/run.ts --impl ada --impl typescript`: all suites green,
  including did:vh.
