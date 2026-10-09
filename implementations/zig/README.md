# vhlog (Zig)

A clean-room Zig implementation of [VH-Log](https://swcurran.github.io/VH-Log/next/)
following the [`vh-log-interop-0` profile](../../docs/profile.md). It was written
only from the spec (pinned at `f2f9fda`), the documents in `docs/`, and the shared
vectors, without reading the other implementations, so it is an independent check
on them.

Standard library only (Zig 0.17): `std.crypto.sign.Ed25519`,
`std.crypto.hash.sha2.Sha256`. The JSON parser/serialiser, JCS, base58btc and
ECMAScript number formatting are written here. Number digits come from the
standard library's Ryu (shortest and closest), laid out with the ECMAScript
`Number::toString` rules.

```sh
zig build -Doptimize=ReleaseSafe   # builds zig-out/bin/vh-log-driver
zig build test                     # unit, end-to-end and ../../vectors tests
node ../../harness/run.ts --impl zig   # from here, or `node harness/run.ts --impl zig` at the repo root
```

## API (`@import("vhlog")`)

| Area | Functions |
| --- | --- |
| JSON / JCS | `parseJson`, `canonicalize`, `canonicalizeText`, `json.stringify` |
| Encodings | `base58Encode`, `base58Decode`, `sha256Multihash`, `hashString`, `encodeMultikey`, `decodeMultikey`, `multikeyFromSeed`, `keyHash` |
| eddsa-jcs-2022 | `createProof`, `verifyProof` |
| Hashes | `scid`, `entryHash` |
| Log Controller | `createLog`, `updateLog`, `witnessProof` |
| Resolver | `verifyLog`, `resolve` (`ResolveRequest`: options, `copies`, `retained_version_id`), `ErrorCode` |

Every function takes an explicit allocator; results that own memory have
`deinit()`. `Resolution.toValue` gives the driver-protocol JSON.

## Layout

- `src/json.zig` — parser (doubles, last duplicate key wins, lone surrogates
  flagged, 1e400 rejected), compact and canonical (RFC 8785) output.
- `src/numfmt.zig` — ECMAScript number formatting.
- `src/codec.zig` — base58btc, multihash, multikey.
- `src/proof.zig` — eddsa-jcs-2022.
- `src/log.zig` — SCID, entry hash, create/update/witness.
- `src/resolve.zig` — verification (profile §4 check order), witnesses,
  partial validity, version selection, copies and retained versionIds.
- `src/ops.zig` — the JSON Lines driver protocol; `src/main.zig` — the driver.
- `src/tests.zig` — end-to-end tests and the shared vectors.
