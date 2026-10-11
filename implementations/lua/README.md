# VH-Log for Lua

Native Lua controller, resolver, JSON parser, canonicalization traversal, and
base58 encoding for the complete `vh-log-interop-0` profile. A small C++ module
provides libsodium Ed25519/SHA-256 and shortest binary64 digits via
`std::to_chars`; Lua applies the ECMAScript number formatting rules.

Requires Lua 5.4 or 5.5, a C++17 compiler, pkg-config, Lua headers, and libsodium.
On Ubuntu install `lua5.4 liblua5.4-dev libsodium-dev pkg-config g++`.
On macOS: `brew install lua libsodium pkgconf`.

```sh
cd implementations/lua
sh build.sh
lua driver.lua
# From the repository root:
node harness/run.ts --impl lua --impl typescript
VH_TEST_IMPLS=lua node --test harness/driver-regressions.test.ts
```

Set `LUA_PKG=lua5.4` if pkg-config needs an explicit Lua version. Build the module
against the same Lua ABI used at runtime. To embed the library, put this
directory on both `package.path` and `package.cpath`:

```lua
local vh = require('vh_log')
local json = require('json')
local O, A = json.object, json.array
local seed = string.rep('01', 32) -- Example only; use fresh seeds in an app.
local initial = vh.create(O{
  state = O{id = 'example:{SCID}'},
  parameters = O{updateKeys = A{vh.multikey(seed)}},
  versionTime = '2026-01-01T00:00:00Z', signers = A{seed},
})
local resolved = vh.resolve(O{
  log = initial.log, now = '2026-01-02T00:00:00Z',
})
```

Use `json.object`, `json.array`, and `json.null` to distinguish empty containers
and JSON null. `json.parse` constructs these values and rejects unsafe JSON.
The API also exposes `update`, `sign`, `verify`, `scid`, `entry_hash`, and
`dispatch`. Results follow the [interop protocol](../../docs/interop-protocol.md).
