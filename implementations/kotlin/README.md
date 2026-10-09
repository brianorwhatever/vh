# vh-log (Kotlin / JVM)

A Kotlin implementation of VH-Log for the [interop profile](../../docs/profile.md):
JCS, base58btc/multihash/multikey, `eddsa-jcs-2022` proofs, the Log Controller
operations, log verification and resolution (version selection, partial
validity, witnesses, copy comparison and retained `versionId`s). It targets
JVM 17 bytecode and depends only on the Kotlin standard library. Ed25519 comes
from the JDK, and JSON parsing and serialisation are built in, so numbers,
key order and duplicate keys follow RFC 8785.

```kotlin
import org.vhlog.*

val seed = "01".repeat(32)
val key = Ed25519Signer.fromSeedHex(seed)

val created = VHLog.createLog(
    state = JsonObject("id" to JsonString("example:{SCID}")),
    parameters = JsonObject("updateKeys" to JsonArray(JsonString(key.multikey))),
    versionTime = "2026-01-01T00:00:00Z",
    signers = listOf(seed),
)
val updated = VHLog.updateLog(
    created.log,
    JsonObject("id" to JsonString("example:${created.scid}"), "name" to JsonString("updated")),
    "2026-01-02T00:00:00Z",
    listOf(seed),
    // parameters: defaults to {}; use {"deactivated": true} to deactivate
)

when (val r = VHLog.resolve(ResolveRequest(updated.log, now = "2026-06-01T00:00:00Z"))) {
    is ResolveResult.Resolved -> println("${r.state} ${r.metadata.versionId}")
    is ResolveResult.Failed -> println("${r.error.code} ${r.error.message}")
}
```

From Java, every entry point is a static method (`VHLog.createLog(...)`,
`Jcs.canonicalize(...)`, `Proofs.verify(...)`) and the data classes have
`@JvmOverloads` constructors.

`ResolveRequest` also takes a parsed witness file (`witness`: Kotlin `null` means
none was found, `JsonNull` is a malformed file), `options` (`ResolveOptions`:
`versionId` / `versionTime` / `versionNumber` / `minCopies`), watcher `copies`
(`CopyInput.Available` / `CopyInput.Unavailable`) and a `retainedVersionId`.
Failures carry an `ErrorCode` from profile §6, and `ResolveResult.toJson()`
gives the protocol's JSON form. `VHLog.verifyLog` returns the valid, witnessed
prefix of a log and its first failure.

| File | Contents |
| --- | --- |
| `Json.kt` | JSON value model, strict parser, compact serialiser, I-JSON check |
| `Jcs.kt` | RFC 8785 canonicalisation and ECMAScript number formatting |
| `Encoding.kt` | base58btc, hex, multikey, SHA-256 multihash |
| `Ed25519.kt` | Seed-derived Ed25519 signer and verification (JDK provider) |
| `Proof.kt` | `eddsa-jcs-2022` create/verify |
| `Log.kt` | SCID and entry hashes, `createLog`, `updateLog`, `witnessProof` |
| `Verify.kt` | Per-entry checks, parameters, witnesses, `verifyLog` |
| `Resolve.kt` | Options, version selection, copies, retained `versionId` |
| `driver/Driver.kt` | Interop driver (JSON Lines on stdin/stdout) |

## Build and test

JDK 17 or later (CI and the harness use JDK 21):

```sh
./gradlew test          # unit, end-to-end and shared-vector tests (../../vectors)
./gradlew installDist   # driver at build/install/vh-log-driver/bin/vh-log-driver
node ../../harness/run.ts --impl kotlin   # from anywhere in the repo
```
