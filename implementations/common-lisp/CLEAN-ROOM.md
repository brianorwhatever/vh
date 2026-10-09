# Clean-room notes

This implementation was built without reading any other implementation in
this repository, its git history, or `tools/generate-vectors.ts`. The only
sources were:

- the pinned spec, `swcurran/VH-Log@f2f9fda` (`spec/*.md`);
- `docs/profile.md`, `docs/interop-protocol.md`, `docs/spec-notes.md` and the root `README.md`;
- `vectors/**`, `harness/run.ts` and `implementations.json`;
- RFC 8785, RFC 8032, ECMA-262 `Number::toString`, the multibase/multihash/multikey
  conventions, and Ironclad's source and documentation.

The vectors found two bugs in my own code: exponent formatting, and a
partially valid reference copy being marked `behind`. After those fixes,
every suite passes. Nothing below was learned from another implementation.

## 1. Interpretations the vectors forced

The documents allowed more than one reading of these, and the vectors pinned
one:

1. **The primary copy appears in `metadata.copies`** as `{"source": "primary", …}`,
   alongside the supplied copies (`copies/*`). The protocol's example lists only
   watcher sources.
2. **`metadata.witness` is the config at the last valid entry, while
   `updateKeys`/`nextKeyHashes` are the accumulated values at the resolved
   entry.** In `witnesses/replace-list-new-witness-too-early`, entry 2 fails,
   so `witness` is entry 1's list. In `authorization/key-rotation`, the
   resolved entry 3 sets no keys but reports entry 2's.
3. **Request-level errors carry `"version": null` explicitly**, not an absent
   key (`not-found`, `invalid-option`, `min-copies-not-met`, empty log). The
   harness compares `err.version !== expect.version`.
4. **Witness ids must be `did:key:` plus a decodable Ed25519 multikey**, or the
   `witness` parameter is `invalid-parameter` (`parameters/witness-id-not-did-key`).
   Profile §3 says what a witness id *is*, not that other ids are malformed.
5. **`updateKeys` entries must decode as Ed25519 multikeys, and `nextKeyHashes`
   entries as multihashes** (`parameters/update-keys-not-multikey`,
   `next-key-hashes-not-multihash`).
6. **An entry hash that isn't base58 is `invalid-version-id`; one that is
   base58 but not SHA-256 is `invalid-hash-algorithm`** (`version-id/entry-hash-not-base58`
   vs `sha512-entry-hash`).
7. **Line splitting:** a final `\n` does not start an entry, a blank line in
   the middle is `invalid-log` at that line, and an empty log is `invalid-log`
   with no version (`structure/*`).
8. **A copy that fails verification before a reference is chosen is still
   reported** (`invalid` + `copy-invalid`), including the primary
   (`copies/invalid-primary`).

## 2. Choices where the documents are silent

None of these is exercised by a vector, as far as I can tell. They are the
places where a second clean-room implementation is most likely to differ.

| # | Situation | Choice made here |
| --- | --- | --- |
| 1 | A line after the deactivating entry that is also not JSON | `entry-after-deactivation` (profile check 1 runs before parsing). |
| 2 | `logVersion` present but not a string | `invalid-parameter` (wrong type), not `unsupported-log-version`. |
| 3 | Order inside profile check 3 when several parameters are bad | `null` values, then `logVersion`, `scid`, `updateKeys`, `nextKeyHashes`, `witness`, `watchers`, `deactivated`, `ttl`, then pre-rotation. |
| 4 | `ttl` upper bound | Inclusive: `0 ≤ ttl ≤ 2^31` ("Range 0 to 2^31"). |
| 5 | `nextKeyHashes` entry that is a well-formed SHA-512 multihash | `invalid-parameter`: under `vh-log:1.0` it can never match a key hash. |
| 6 | Extra properties in a `witness` config or in a `witnesses[]` item | Ignored. |
| 7 | Witness file record without a string `versionId` or an array `proof` | The whole file is `invalid-witness-file`. A non-object item *inside* `proof` is ignored as unattributable. |
| 8 | Where `invalid-witness-file` is reported | At the first entry that needs witnessing, and only if one does. |
| 9 | Witness proofs for an entry that failed a non-witness check | Ignored. Only the valid prefix counts as "in the log" for profile §3. |
| 10 | SCID verification when the SCID also appears in an object *key* | Replace in the serialised entry, re-parse, then hash the JCS of the result (not the replaced JCS text directly). These agree unless the SCID appears in a key. |
| 11 | No copy passes full verification | Resolve the first copy (primary first) with a non-empty valid prefix, under the partial-validity rule. It is reported `current`. If none has a valid first entry, fail with the primary's error. |
| 12 | Verifying a longer copy's additional entries | Continue from the reference's last entry state, using the union of the reference's and the copy's witness files. |
| 13 | `versionTime` target when the first invalid entry's own `versionTime` is unreadable | Fail with the invalidating error only if the match would be the last valid entry. |
| 14 | `ttl` and `watchers` in metadata for an earlier target | Taken from the last valid entry ("current"), like `witness`. |
| 15 | Malformed `retainedVersionId` (no version number) | `invalid-option`. |
| 16 | `versionNumber`/`minCopies` given as `2.0` | Accepted: JSON numbers are doubles, so `2.0` is `2`. |
| 17 | `verify` primitive and `proofPurpose` | Not checked by `verify`. It is checked for entry and witness proofs during resolution. |
| 18 | Multikey with a non-canonical base58 encoding (an extra leading `1`) | Rejected: it must re-encode to the same string. |
| 19 | Digits in `versionTime` | ASCII `0`–`9` only. Some languages' "is digit" accepts other Unicode digits. |
| 20 | `copies` in metadata | Present only when the request has `copies`. A `retainedVersionId` alone doesn't add it. |

## 3. Spec gaps (beyond `docs/spec-notes.md`)

These come from building the copy logic from the spec text alone:

- **No copy verifies.** *Comparing Copies* says to discard a failing copy and
  "choose another", but not what happens when none is left, or how that
  interacts with partial validity (*Read* step 10). Choice 11 above fills the
  gap.
- **The reference copy's own status.** The `copies` status list defines
  `current` relative to "the reference copy" but never says the reference copy
  is itself listed. The vectors show it is (§1.1).
- **Witnessing an extension.** "Verify only the copy's additional entries"
  doesn't say which witness file approves them: the copy's, the reference's,
  or both. A watcher's witness file could legitimately hold only the newest
  proofs. Choice 12 above uses both.
- **`retained-version-not-found` vs failing.** The spec allows either. The
  vectors expect the warning, which this implementation follows.
- **The metadata for an earlier target.** *Resolution Result* calls `ttl`,
  `watchers` and `witness` "current" without saying whether that means at the
  target or at the last valid entry. Only `witness` is pinned (§1.2).
- **Proof-level error order inside `invalid-proof`.** Profile §4 groups `type`,
  `cryptosuite`, `proofPurpose`, `proofValue` and the signature under one code,
  so order doesn't matter for the result. It would matter for messages or for
  finer error codes.

## 4. What the documents got right

Everything needed for the shared vectors could be derived from the
profile, the protocol and the spec. The profile's explicit check order (§4) and the
"exactly one check fails" rule for vectors made error codes unambiguous.
Spec notes 17–21 (JCS numbers as doubles, UTF-16 key order, double formatting,
I-JSON, JSON Lines splitting) named every hazard that came up while writing the
JSON layer. The vectors caught the one formatting bug introduced.
