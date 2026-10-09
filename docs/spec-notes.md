# Spec Notes

These are issues found in VH-Log
[`f2f9fda`](https://github.com/swcurran/VH-Log/tree/f2f9fda/spec) while building
interoperable implementations. Each note says what [`profile.md`](profile.md)
does about it. They are candidates for spec issues or PRs. None of them blocks
implementation.

Section links point at the pinned
[`specification.md`](https://github.com/swcurran/VH-Log/blob/f2f9fda/spec/specification.md).

## Errors

1. **The entry-hash example does not reproduce.** In *Generate Entry Hash*,
   JCS → SHA-256 multihash → base58btc of the example gives
   `QmXoHG2Z6Hg1kmryaRxcqgzF6nv2vgLZnYHvGirL9t2a8U`, not the stated
   `QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ`. All eight implementations
   here agree on the computed value (`vectors/primitives.json`, `entryHash[1]`).
   So does the independent didwebvh-ts (`deriveHash`, at `1622d03`). The
   example also lists the SCID itself as the input `versionId`, and the SCID
   then also appears in `parameters.scid`, so it can't double as a SCID
   example. The spec's `CLAUDE.md` asks for test vectors for every
   cryptographic operation; `vectors/` could fill that gap.
2. **The `nextKeyHashes` example value isn't base58btc.** The parameters example
   uses `enkkrohe5ccxyc7zghic6qux5inyzthg2tqka4b57kvtorysc3aa`, which looks like
   base32. Every other hash, including the entry-hash example's `nextKeyHashes`,
   is a base58btc multihash (`Qm…`).
3. **The pre-rotation key hash formula leaves out the algorithm.** It's written
   `base58btc(multihash(multikey))`, but the next line describes a
   `<hash algorithm>` parameter. The spec doesn't say whether the multikey's
   string or its decoded bytes are hashed. The profile hashes the UTF-8
   *string* (did:webvh practice).

## Left unspecified (the profile fills these in)

4. **How a proof names its key.** *Authorized Keys* says the `verificationMethod`
   "resolves to a multikey" in `updateKeys`, but not how. → Profile:
   `did:key:<mk>#<mk>`.
5. **What a witness signs.** The witness file holds proofs, but the signed
   document isn't defined. → Profile: `{"versionId": …}` (as in did:webvh).
6. **Multiple proofs per entry.** `proof` is an array ("one or more"), but the
   spec doesn't say whether one valid authorised proof is enough or all must be
   valid. → Profile: all must be valid and authorised.
7. **Partial validity.** *Read* step 10 allows either "invalidating the entire
   log" or marking entries from the first invalid one. Implementations will
   give different answers for the same log unless one is chosen. → Profile:
   keep the valid prefix, and warn with `invalid-entries`.
8. **Check order and error identity.** The spec defines what fails but not
   which failure is reported when several apply, and it has no error codes.
   A shared test suite needs both. → Profile §4 and §6. Worth upstreaming as
   a non-normative error-code registry.
9. **Where the pre-rotation rule sits in the check order.** The rule is *Read*
   step 7, but the active `updateKeys` that step 2 uses depends on it. → Profile
   checks pre-rotation with the parameters (step 1).
10. **Which witness list applies to an entry once lists have changed.** *Verifying
    Witness Proofs* step 5 accepts proofs on "any later" entry, but the list
    those approvals are counted against isn't stated when later entries change
    the list. → Profile: the list that applies to entry *k* (§3).
11. **Clock-dependent checks.** The future-time check depends on the resolver's
    clock. For reproducible results the profile passes `now` in the request, and
    sets the tolerance to 300 s (the spec says "SHOULD … no more than 5 minutes").

## Inconsistencies

12. **Unknown parameters.** *VH-Log Parameters* says `parameters` "MUST only
    include properties defined in" the spec or the specialisation. But
    *Specialisation-defined Parameters* says resolvers "MUST ignore unrecognised
    parameters". → Profile: ignore them.
13. **Copy comparison trusts matching `versionId`s.** In *Comparing Copies*, a
    copy whose last `versionId` matches the reference "needs no further
    verification". A copy with an edited `state` but unchanged `versionId`s is
    therefore reported `current`. The reference copy is still what gets resolved,
    so this is safe, but the `copies` status can be misleading. Vector:
    `copies/tampered-copy-same-version-ids`.
14. **`versionId` doesn't cover proofs.** Two entries with the same content but
    different signers (even an unauthorised one) have the same `versionId`. Fork
    detection by `versionId` can't see a proof swap. This is harmless for
    integrity, because the reference copy is fully verified, but worth stating.
15. **Generation rules that can't be verified.** "The timestamp MUST be the time
    the entry will be retrieved … or before" can't be checked, apart from the
    future tolerance.

16. **`deactivated` doesn't say whether it carries over.** Other parameters
    "retain the most recent prior value" when omitted; `deactivated` has no such
    rule. It makes no visible difference, because nothing may follow a
    deactivating entry. Witness-id NFC normalisation likewise has no effect
    under a did:key witness profile, since those ids are ASCII.

## Interop hazards worth a sentence in the spec

17. **JCS numbers are doubles.** RFC 8785 serialises every number as an IEEE-754
    double, so a `state` containing `123456789012345678` hashes as
    `…680`. Languages with arbitrary-precision integers (Python, Elixir, Rust's
    serde_json) silently break the hash chain unless they convert. Vector:
    `structure/jcs-numbers-in-state`.
18. **JCS key order is by UTF-16 code units.** Libraries that sort by code point
    or by UTF-8 bytes disagree when there are non-BMP keys (e.g. emoji). Vector:
    `primitives.json` `jcs[5]`.
19. **Formatting doubles is easy to get subtly wrong.** Rust's `{:e}` gives
    the shortest digits but not always the closest ones (`896365914996807.2`
    comes out as `…807.3`), so about 0.1% of random doubles hashed differently
    from ECMAScript. The original vectors didn't catch this; `jcs[2]` now does.
20. **Edge cases of the JSON parser.** `1e400`, lone surrogate escapes and
    duplicate keys are handled differently by different parsers. The spec
    should require I-JSON (RFC 7493) log lines; the profile pins this (§4).
21. **JSON Lines and U+2028.** Line readers in some languages (Node's
    `readline`, Python's `str.splitlines`) also split on U+2028/U+2029, which JSON
    allows unescaped inside strings. The spec should say a log is split on `\n`
    only.
