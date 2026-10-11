# VH-Log for Haskell

Native Haskell controller and resolver for the complete `vh-log-interop-0`
profile. JSON uses an explicit sum type, binary64 numbers, UTF-16 key ordering,
and exact rational rounding for RFC 8785 number output. The protocol logic is
pure; deterministic cryptographic primitives call libsodium through the FFI.

Requires GHC 9.6 or newer, pkg-config, and libsodium headers/libraries. Only GHC
boot packages are used; no Hackage downloads are needed for the direct build.
On Ubuntu install `ghc libsodium-dev pkg-config`; on macOS use
`brew install ghc libsodium pkgconf`.

```sh
cd implementations/haskell
sh build.sh
bin/vh-log-driver
# Optional Cabal library/executable build:
cabal build all
# From the repository root:
node harness/run.ts --impl haskell --impl typescript
VH_TEST_IMPLS=haskell node --test harness/driver-regressions.test.ts
```

The Cabal library exposes `VHLog`, `Json`, and `Crypto`:

```haskell
import Json
import qualified Crypto
import qualified VHLog

seed = concat (replicate 32 "01") -- Example only; use fresh seeds in an app.
initial = VHLog.create (object
  [ ("state", object [("id", str "example:{SCID}")])
  , ("parameters", object [("updateKeys", array [str (Crypto.multikey seed)])])
  , ("versionTime", str "2026-01-01T00:00:00Z")
  , ("signers", array [str seed])
  ])
resolved = VHLog.resolve (object
  [("log", get initial "log"), ("now", str "2026-01-02T00:00:00Z")])
```

`Json.parse` returns `Either String J`. `VHLog.resolve` returns the structured
validity result specified by the [interop protocol](../../docs/interop-protocol.md).
The API also includes `update`, `sign`, `verify`, `scid`, `entryHash`, and
`dispatch`. Controller calls expect well-typed inputs and valid seed encodings;
malformed controller requests can raise exceptions, which the driver catches.
