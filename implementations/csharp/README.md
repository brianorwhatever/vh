# VH-Log (C#)

.NET 10 library; System.Text.Json and Bouncy Castle Ed25519.

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic runs in C#; it does not call another implementation.

## Setup

Install the .NET 10 SDK. BouncyCastle.Cryptography is pinned in the project
and `packages.lock.json`.

```sh
dotnet restore --locked-mode
dotnet build -c Release
```

## Library usage

Reference `VHLog.csproj` and use `VHLog.Log`:

```csharp
string seed = new string('1', 64);
var created = Log.Create(Log.Obj(
    "state", Log.Obj("id", "example:{SCID}"),
    "parameters", Log.Obj("updateKeys", new JsonArray(Log.Multikey(seed))),
    "versionTime", "2026-01-01T00:00:00Z",
    "signers", new JsonArray(seed)));
var result = Log.Resolve(Log.Obj("log", created["log"], "now", "2026-06-01T00:00:00Z"));
```

Import `System.Text.Json.Nodes` and `VHLog`. `Parse` validates JSON and
converts numbers to binary64. `Canonicalize` implements RFC 8785. Helpers
clone input nodes so callers retain ownership.

## Verification and driver

From the repository root:

```sh
node harness/run.ts --impl csharp --impl typescript
VH_TEST_IMPLS=csharp node --test harness/driver-regressions.test.ts
```

The shared harness checks primitives, resolution, generation, external
reference logs, and cross-resolution. Boundary tests additionally check
binary64 formatting, Unicode, malformed-request recovery, LF framing,
and the supported calendar endpoints.

From this directory, start the JSON Lines driver with:

```sh
dotnet bin/Release/net10.0/VHLog.dll
```

See the [driver protocol](../../docs/interop-protocol.md) for request and
response shapes. Logs and witness files are supplied by the caller; the
resolver does not fetch network resources.
