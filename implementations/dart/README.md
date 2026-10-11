# VH-Log for Dart

Native Dart implementation of the complete `vh-log-interop-0` profile. Uses
`crypto` for SHA-256 and `ed25519_edwards` for synchronous Ed25519. Suitable for
Dart and Flutter applications; the command-line driver uses `dart:io`, while
the library does not. Browser/JavaScript compilation is not currently tested.

Requires Dart 3.6 or newer. Dependencies are pinned in `pubspec.lock`.

```sh
cd implementations/dart
dart pub get
dart analyze
sh build.sh
# From the repository root:
node harness/run.ts --impl dart --impl typescript
VH_TEST_IMPLS=dart node --test harness/driver-regressions.test.ts
```

Add this directory as a path dependency named `vh_log`, then import the library:

```dart
import 'package:vh_log/vh_log.dart' as vh;

final seed = '01' * 32; // Example only; use a securely generated seed in an app.
final initial = vh.create({
  'state': {'id': 'example:{SCID}'},
  'parameters': {'updateKeys': [vh.multikey(seed)]},
  'versionTime': '2026-01-01T00:00:00Z',
  'signers': [seed],
});
final resolved = vh.resolve({
  'log': initial['log'], 'now': '2026-01-02T00:00:00Z',
});
```

`create`, `update`, `resolve`, `sign`, `verify`, `scid`, `entryHash`, and
`multikey` are ordinary library functions. `dispatch` implements the shared
[driver operations](../../docs/interop-protocol.md). Use `parse` for external
JSON to enforce finite binary64 numbers and valid Unicode; `jcs` canonicalizes
those values. Resolution returns a structured `valid` result, including
partial validity, witness requirements, selectors, and copy/fork metadata.
