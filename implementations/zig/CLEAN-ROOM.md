# Clean-room notes

The VH-Log part of this implementation was written only from the pinned
VH-Log spec, `docs/` and the shared vectors, without reading any other
implementation (see [`README.md`](README.md)).

## did:vh

did:vh support (`src/didvh.zig`, the `Specialisation` hook in
`src/resolve.zig`, the `method` default in `src/log.zig`) was added under the
same rule: no other implementation, its git history or diffs,
`tools/generate-vectors.ts` or `tools/generate-didvh-vectors.ts` was read. The
sources were:

- `docs/didvh-profile.md` (`didvh-interop-0`), the "did:vh operations"
  section of `docs/interop-protocol.md`, and `docs/profile.md`;
- the pinned DIF spec, `decentralized-identity/didvh@cc2eff6`, where the
  profile links to it;
- `vectors/didvh/**` and `harness/run.ts` (`didvh`, `didvhCross`,
  `compareDidResolution`);
- the Zig 0.17 standard library documentation (`std.unicode`, `std.ascii`).

The only bug the vectors found was in my own code: a `u1` overflow when
counting `didLog`/`srcLog` with `@intFromBool`. These are the places where the
profile left room, and where another implementation could differ without a
vector noticing:

| # | Profile passage | Choice made here |
| --- | --- | --- |
| 1 | §5 step 4: "the log needs witnessing, meaning some entry has an active witness list" | Originally decided syntactically, before verification. Superseded: see "The log needs witnessing" below. |
| 2 | §4 step 3: "The query is split on `&`. Each part MUST contain `=`." | Applied literally: `did:vh:…?` (an empty query) and `?a=1&&b=2` (an empty part) are `invalidDidUrl`. |
| 3 | §3.2 step 4: "one trailing `/` is removed" | Removed from the whole value before the authority and path checks, so `ipfs://x/` is valid and `https://h/a//` fails on its empty last segment. |
| 4 | §3.2 steps 3 and 5: other schemes need only "`//` and a non-empty authority" | For schemes other than `https`, the authority and path are not checked further. |
| 5 | §3.1 step 4: "A port is 1–5 digits" | An empty port (`https://h:/x`) is invalid. |
| 6 | §3.1 step 5: `file://localhost/<path>` | `file://localhost` with no `/` after the host is invalid (no path). `file:///` is valid. |
| 7 | §5 step 2: the order of the option checks | Presence, `didLog`/`didWitness` types, references, selectors, then `checkWatchers`, `extraWatchers`, `minCopies`, `includeDidLog`. All give `invalidOptions`, so order only changes `detail`. |
| 8 | §5 Deactivation: "no version selector (`versionId`, `versionTime` or `versionNumber`) is given" | A selector is given when its key is present in the options (a bad value already failed as `invalidOptions`). Replaces the earlier "last valid entry" reading; see below. |
| 9 | "Number types matter: `ttl` and witness `threshold` are JSON integers" | Numbers are `f64` here, as for all JSON; integral values are written without a fraction (ECMAScript formatting), so `3600` and `2` come out as integers. |
| 10 | §2: the state check needs `state` to be an object | VH-Log's structure check already requires an object (`invalid-entry`), so the state check only compares `state.id`; a missing or non-string `id` is `invalid-state`. |
| 11 | §5: `didLog` "holds the original lines of the valid entries" | The lines as split on `\n`, byte for byte, each followed by `\n`. |
| 12 | §1: "`method` may appear in later entries, under the same rules as `logVersion`" | The same membership rule as `logVersion`; with one accepted value, "lowering" can't occur. |

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
`docs/profile.md` §3 and §4, those three vectors in
`vectors/didvh/resolution/options.json`, and the harness output. No other
implementation, its history or diffs, or `tools/generate-*.ts` was read.

Change: the per-entry loop of `verifyWith` in `src/resolve.zig` moved into
`checkEntries`, and a new `resolver.needsWitnessing` runs it alone (with the
did:vh specialisation, so check 8 applies) and looks at each valid entry's
`witness_applies`. `src/didvh.zig` uses it for both step 4 and `didWitness`,
so `didWitness` no longer depends on witness verification either: an entry
that passes the per-entry checks but is not witnessed still counts.

### Selecting the deactivating entry (profile change)

`docs/didvh-profile.md` §5 "Deactivation" changed. A deactivated DID now has
`didDocument: null` only when no version selector (`versionId`,
`versionTime` or `versionNumber`) is given. With any selector the selected
entry's document is returned, including the deactivating entry itself, and
`deactivated` stays `true`. Before, the document was withheld whenever the
resolved entry was the last valid entry, selected or not. Spec note 24 now
records the same reading. The vectors `deactivation/deactivating-version`
(selected by `versionId`) and the new `deactivation/deactivating-version-time`
(a `versionTime` after the last entry, so it resolves to the same entry as no
selector would) pin it.

Read for this change, and nothing else: the new §5 "Deactivation" text, spec
note 24 in `docs/spec-notes.md`, the docs and vectors parts of commit
`1206c43`, those two vectors in `vectors/didvh/resolution/deactivation.json`,
and the harness output. No other implementation, its history or diffs, or
`tools/generate-*.ts` was read.

Change: in `resolve` in `src/didvh.zig`, `didDocument` is `null` when
`deactivated and selectors == 0`, using the selector count the option
checks already keep. The `latest` comparison is gone. `zig build test` and
the harness pass.
