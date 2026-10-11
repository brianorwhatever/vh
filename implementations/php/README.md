# VH-Log (PHP)

PHP 8.3+; Sodium and mbstring extensions.

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic runs in PHP; it does not call another implementation.

## Setup

Use PHP 8.3 or newer with `sodium` and `mbstring` enabled.
On macOS: `brew install php`. On Debian/Ubuntu install `php-cli` and
`php-mbstring` (Sodium is included in current PHP distributions).
No Composer dependencies are required.

## Library usage

```php
require 'src/VHLog.php';
use VHLog\Log;
$seed = str_repeat('11', 32);
$created = Log::create((object)[
    'state' => (object)['id' => 'example:{SCID}'],
    'parameters' => (object)['updateKeys' => [Log::multikey($seed)]],
    'versionTime' => '2026-01-01T00:00:00Z',
    'signers' => [$seed],
]);
$result = Log::resolve((object)['log' => $created['log'], 'now' => '2026-06-01T00:00:00Z']);
```

JSON objects use `stdClass`, including empty objects; arrays remain PHP
arrays. Use `Log::parse` to normalize numbers to binary64 and `Log::jcs`
for RFC 8785 output. The driver sets `serialize_precision=-1`; library
callers should keep PHP's default value of `-1`.

## Verification and driver

From the repository root:

```sh
node harness/run.ts --impl php --impl typescript
VH_TEST_IMPLS=php node --test harness/driver-regressions.test.ts
```

The shared harness checks primitives, resolution, generation, external
reference logs, and cross-resolution. Boundary tests additionally check
binary64 formatting, Unicode, malformed-request recovery, LF framing,
and the supported calendar endpoints.

From this directory, start the JSON Lines driver with:

```sh
php driver.php
```

See the [driver protocol](../../docs/interop-protocol.md) for request and
response shapes. Logs and witness files are supplied by the caller; the
resolver does not fetch network resources.
