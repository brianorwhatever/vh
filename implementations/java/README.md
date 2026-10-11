# VH-Log (Java)

JDK 21 only. Native Java library with its own strict JSON parser and JCS formatter.

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic runs in Java; it does not call another implementation.

## Setup

Install JDK 21 or newer, with `java` and `javac` on `PATH`.

```sh
sh build.sh
```

## Library usage

Compile the sources in `src/org/vhlog` and import `org.vhlog.VHLog`:

```java
String seed = "11".repeat(32);
var created = VHLog.create(VHLog.obj(
    "state", VHLog.obj("id", "example:{SCID}"),
    "parameters", VHLog.obj("updateKeys", java.util.List.of(VHLog.multikey(seed))),
    "versionTime", "2026-01-01T00:00:00Z",
    "signers", java.util.List.of(seed)));
var result = VHLog.resolve(VHLog.obj("log", created.get("log"), "now", "2026-06-01T00:00:00Z"));
```

`Json.parse` produces maps, lists, strings, booleans, null, and binary64
numbers. `Json.stringify` produces canonical RFC 8785 JSON. Ed25519 and
SHA-256 use JDK security providers; no Kotlin runtime is involved.

## Verification and driver

From the repository root:

```sh
node harness/run.ts --impl java --impl typescript
VH_TEST_IMPLS=java node --test harness/driver-regressions.test.ts
```

The shared harness checks primitives, resolution, generation, external
reference logs, and cross-resolution. Boundary tests additionally check
binary64 formatting, Unicode, malformed-request recovery, LF framing,
and the supported calendar endpoints.

From this directory, start the JSON Lines driver with:

```sh
java -cp build/classes org.vhlog.Driver
```

See the [driver protocol](../../docs/interop-protocol.md) for request and
response shapes. Logs and witness files are supplied by the caller; the
resolver does not fetch network resources.
