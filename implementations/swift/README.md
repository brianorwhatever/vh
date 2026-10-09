# VH-Log — Swift

A Swift 6 implementation of [VH-Log](https://github.com/swcurran/VH-Log) that
follows this repository's interop profile ([`docs/profile.md`](../../docs/profile.md)).
It builds on macOS, iOS and Linux. Its only dependency is
[swift-crypto](https://github.com/apple/swift-crypto), used for SHA-256/512 and
Ed25519 verification.

```sh
swift build -c release --product vh-log-driver   # interop driver (docs/interop-protocol.md)
swift test                                       # unit, end-to-end and shared-vector tests
node ../../harness/run.ts --impl swift           # from here, or from the repo root without ../../
```

## Use

```swift
import VHLog

let key = try Ed25519Signer(seedHex: "90930409…eaaa")
let created = try createLog(state: ["id": "example:{SCID}"],
                            parameters: ["updateKeys": [.string(key.multikey)]],
                            versionTime: "2026-01-01T00:00:00Z", signers: [key])
let updated = try updateLog(log: created.log, state: ["id": .string("example:\(created.scid)")],
                            versionTime: "2026-01-02T00:00:00Z", signers: [key])

switch resolve(ResolveInput(log: updated.log, now: "2026-06-01T00:00:00Z",
                            options: ResolveOptions(versionNumber: 1))) {
case .resolved(let r): print(r.state, r.metadata.versionId, r.firstInvalidVersion as Any)
case .failed(let error): print(error.code.rawValue)      // e.g. "scid-mismatch"
}
```

| Area | API |
| --- | --- |
| JSON | `JSONValue`, `JSONObject` (ordered, exact code-unit keys), `JSONValue.parse`, `serialized()` |
| Encodings | `JCS.canonicalize`, `formatECMAScriptNumber`, `Base58`, `Hex`, `Multihash` (`hashB58`, `keyHash`, `check`), `Multikey` |
| Proofs | `Ed25519Signer`, `DataIntegrity.createProof` / `verifyProof` (`eddsa-jcs-2022`) |
| Log Controller | `createLog`, `updateLog`, `witnessProof`, `computeScid`, `computeEntryHash` |
| Resolver | `verifyLog`, `resolve(_:)`, `resolve(request:)` (driver-shaped JSON), `ResolveOptions`, `LogCopy` |
| Errors | `ErrorCode` (raw values are the profile codes), `VHLogError`, `VHLogInputError` |

## Implementation notes

- **Own JSON parser and serialiser.** `JSONSerialization`/`Codable` lose number
  text, reorder keys and differ between Darwin and Linux. Numbers are parsed as
  doubles and printed as ECMAScript `Number::toString` (Swift's shortest
  round-trip digits, re-notated). Keys sort by UTF-16 code units. Strings and keys
  compare by exact bytes, not by Swift's canonical equivalence, so `"é"` and
  `"e\u{301}"` stay distinct, and `{SCID}` replacement is done on UTF-8 bytes.
  Lone surrogate escapes and non-finite numbers make a log line `invalid-log`.
- **Deterministic Ed25519 signing.** CryptoKit (which swift-crypto uses on Apple
  platforms) produces *randomised* Ed25519 signatures, so generated logs wouldn't
  reproduce the vectors. Signing therefore uses a small port of TweetNaCl's
  RFC 8032 arithmetic (`Ed25519.swift`); verification uses swift-crypto. Signing
  takes about 1.5 ms in release builds, much longer in debug builds.
- The driver reads stdin with `readLine` (splits on `\n` only) and writes each
  response with an unbuffered `write(2)`.
