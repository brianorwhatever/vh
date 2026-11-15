# VH-Log (C++)

C++17 library with value-based JSON; nlohmann/json and libsodium.

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic runs in C++; it does not call another implementation.

It also implements [did:vh](../../docs/didvh-profile.md) in `src/didvh.hpp`
(namespace `vhlog::didvh`): a did:vh log is verified by the same VH-Log code
with a `Specialisation` (`method`, a closed parameter set and the `state.id`
check), and the module adds DID creation and update, `srcLog`/`srcWitness`
and `src` checks, DID URL parsing and offline DID resolution.

## Setup

```sh
# macOS
brew install nlohmann-json libsodium
# Debian/Ubuntu
sudo apt-get install g++ nlohmann-json3-dev libsodium-dev
sh build.sh
```

## Library usage

Include `src/vh_log.hpp` (and `src/didvh.hpp` for did:vh) and link
`src/vh_log.cpp` and `src/didvh.cpp` with `-lsodium`.
Call `sodium_init()` once before using the library.

```cpp
using namespace vhlog;
std::string seed(64, '1');
Json created = create({
    {"state", {{"id", "example:{SCID}"}}},
    {"parameters", {{"updateKeys", Json::array({multikey(seed)})}}},
    {"versionTime", "2026-01-01T00:00:00Z"},
    {"signers", Json::array({seed})}
});
Json result = resolve({{"log", created.at("log")}, {"now", "2026-06-01T00:00:00Z"}});
```

`parse` reads all numbers as binary64; `canonicalize` implements RFC 8785.
`create`, `update`, `sign`, `verify`, `scid`, `entry_hash`, and `resolve` are
independently callable. Results own their values.

## Verification and driver

From the repository root:

```sh
node harness/run.ts --impl cpp --impl typescript
VH_TEST_IMPLS=cpp node --test harness/driver-regressions.test.ts
```

The shared harness checks primitives, resolution, generation, external
reference logs, and cross-resolution. Boundary tests additionally check
binary64 formatting, Unicode, malformed-request recovery, LF framing,
and the supported calendar endpoints.

From this directory, start the JSON Lines driver with:

```sh
bin/vh-log-driver
```

See the [driver protocol](../../docs/interop-protocol.md) for request and
response shapes. Logs and witness files are supplied by the caller; the
resolver does not fetch network resources.
