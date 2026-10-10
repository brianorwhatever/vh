# VH-Log in Forth

A Gforth implementation of the pinned VH-Log specification and
[`vh-log-interop-0`](../../docs/profile.md), including generation, resolution,
pre-rotation, witnesses, historical selection, and copy/fork comparison.
Built from the specification, profile, and shared vectors without reading
another implementation. See [CLEAN-ROOM.md](CLEAN-ROOM.md).

## Build and run

Requires **64-bit Gforth 0.7.3**, a C++17 compiler with floating-point
`std::to_chars`, libtool, libsodium, utf8proc, and nlohmann/json headers.
The driver itself does not require Node; Node 24 is used for the shared harness
and driver regression tests.

macOS (Homebrew and Xcode command-line tools):

```sh
brew install gforth libtool libsodium utf8proc nlohmann-json
```

Ubuntu 24.04:

```sh
sudo apt-get install gforth libtool-bin g++ libsodium-dev libutf8proc-dev nlohmann-json3-dev
```

From this directory:

```sh
sh build.sh
sh run.sh
```

The process reads the shared [JSON Lines protocol](../../docs/interop-protocol.md)
on stdin and writes one response per request. For example:

```sh
printf '%s\n' '{"id":1,"op":"hash","input":{"data":"abc"}}' | sh run.sh
```

`build.sh` compiles `bin/libvhforth.so` (`.dylib` on macOS). Gforth compiles its
FFI bindings on first use and caches them in its normal user cache. Keep the
compiler and libtool installed for that step. `run.sh` sets the library search
paths and accepts an optional Forth source filename.

## Implementation boundary

The protocol is implemented in Forth:

- `json.fs`: JCS traversal, punctuation, and UTF-16 key ordering.
- `crypto.fs`: base58, multihash/multikey, proof configuration, signing inputs,
  proof verification, SCIDs, and entry hashes.
- `controller.fs`: creation, updates, and witness proofs.
- `time.fs`: strict UTC parsing and proleptic Gregorian arithmetic, including year 0000.
- `validation.fs`: ordered entry validation and parameter transitions.
- `witness.fs`: distinct witness approvals and deferred witness verification.
- `selection.fs`, `copies.fs`, `resolver.fs`: partial validity, historical
  selection, matching copies, forks, retained versions, and result metadata.
- `driver.fs`: request dispatch and error recovery.

`native.cpp` is a generic C ABI support library, bound by `native.fs`. It supplies
JSON parsing/storage/string escaping through nlohmann/json, shortest decimal
formatting through C++ `std::to_chars`, UTF-16 comparison and NFC normalization
through utf8proc, and SHA-256/Ed25519 through libsodium. It also supplies byte-string
operations and LF-delimited I/O. It contains no VH-Log validation, hash-chain,
proof-configuration, or copy-selection logic. This is a Forth implementation
with native dependencies, rather than a dependency-free Forth JSON/crypto stack.

Parsed JSON numbers are converted to IEEE-754 doubles. The decimal formatter
applies ECMAScript's fixed/exponent thresholds to the shortest representation.
Malformed UTF-8, lone surrogate escapes, and overflowing numbers are rejected;
duplicate object members retain their last value.

JSON handles belong to a request-scoped arena. Getters return copies, so a
modified child must be stored back with `put`; accepted history snapshots stay
independent. `j-reset` releases the whole arena after each response. Temporary
Forth buffers for sorting and base58 are explicitly freed. Resolver context is
sequential and is not reentrant. Memory use grows with the current request;
this driver does not impose a request-size limit.

For embedding in Gforth, load `resolver.fs` through the launcher, use `json-parse`
to obtain an input handle, then call `create-log`, `update-log`, `sign-proof`,
`verify-proof`, or `resolve-log`. Use `j-dump raw type` to print a result and
`j-reset` only when all its handles are no longer needed. The launcher assumes a
64-bit cell, as required by timestamp arithmetic and the native ABI.

## Tests

```sh
sh run.sh test.fs
node --test driver.test.mjs
```

From the repository root:

```sh
node harness/run.ts --impl forth
node harness/run.ts --update-readme
```

The Forth checks cover encoding, canonicalization, invalid Unicode/numbers,
and calendar boundaries. Driver tests cover malformed-request recovery,
line framing, fork evidence, trusted-prefix reuse, integer bounds, and stack
balance across multiple requests. The shared harness covers all 35 primitives,
158 resolution cases, 18 generation cases, 40 independent didwebvh-ts checks,
and cross-resolution with the other implementations.
