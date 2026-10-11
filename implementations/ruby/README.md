# VH-Log (Ruby)

Ruby 3.4+; standard JSON and OpenSSL libraries.

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic runs in Ruby; it does not call another implementation.

## Setup

Use Ruby 3.4 or newer with its JSON and OpenSSL libraries and OpenSSL 3.
On macOS, `brew install ruby` provides a compatible runtime; the registry
prepends `/opt/homebrew/opt/ruby/bin` when it exists. No gems are required.

## Library usage

```ruby
require_relative 'lib/vh_log'
seed = '11' * 32
created = VHLog.create(
  'state' => {'id' => 'example:{SCID}'},
  'parameters' => {'updateKeys' => [VHLog.multikey(seed)]},
  'versionTime' => '2026-01-01T00:00:00Z',
  'signers' => [seed]
)
result = VHLog.resolve('log' => created['log'], 'now' => '2026-06-01T00:00:00Z')
```

Use `VHLog.parse` to parse text before hashing: it converts JSON numbers to
binary64 as RFC 8785 requires. `VHLog.jcs`, `sign`, `verify`, `create`,
`update`, and `resolve` can be called directly.

## Verification and driver

From the repository root:

```sh
node harness/run.ts --impl ruby --impl typescript
VH_TEST_IMPLS=ruby node --test harness/driver-regressions.test.ts
```

The shared harness checks primitives, resolution, generation, external
reference logs, and cross-resolution. Boundary tests additionally check
binary64 formatting, Unicode, malformed-request recovery, LF framing,
and the supported calendar endpoints.

From this directory, start the JSON Lines driver with:

```sh
ruby driver.rb
```

See the [driver protocol](../../docs/interop-protocol.md) for request and
response shapes. Logs and witness files are supplied by the caller; the
resolver does not fetch network resources.
