# VH-Log for Scala

Native Scala 3 controller and resolver for the complete `vh-log-interop-0`
profile. Uses ujson for JSON values, its own RFC 8785 formatter, and JDK
Ed25519/SHA-256. No other VH-Log implementation is called.

Requires Scala CLI and JDK 21. Scala and ujson versions are pinned in
`project.scala`. Scala CLI can provision JDK 21 during compilation; running
the assembled JAR requires Java 21 on `PATH`.

```sh
cd implementations/scala
sh build.sh
java -jar bin/vh-log-driver.jar
# From the repository root:
node harness/run.ts --impl scala --impl typescript
VH_TEST_IMPLS=scala node --test harness/driver-regressions.test.ts
```

The reusable API is `vhlog.VHLog`. Include `src/VHLog.scala` and the ujson
dependency in a Scala project:

```scala
import vhlog.VHLog
import ujson.*

val seed = "01" * 32 // Example only; generate fresh seeds for real keys.
val initial = VHLog.create(Obj(
  "state" -> Obj("id" -> "example:{SCID}"),
  "parameters" -> Obj("updateKeys" -> Arr(VHLog.multikey(seed))),
  "versionTime" -> "2026-01-01T00:00:00Z",
  "signers" -> Arr(seed)
))
val resolved = VHLog.resolve(Obj(
  "log" -> initial("log"), "now" -> "2026-01-02T00:00:00Z"
))
```

Also exposes `update`, `sign`, `verify`, `scid`, `entryHash`, `parse`, and `jcs`.
Use `parse` for untrusted JSON: it rejects non-finite numbers and lone Unicode
surrogates. Resolution results follow the shared
[driver protocol](../../docs/interop-protocol.md), including partial validity,
witnesses, version selectors, and copy/fork handling.
