# Ada VH-Log

Independent Ada 2022 implementation of the pinned VH-Log specification and
`vh-log-interop-0` profile. JSON parsing, canonical ordering, encodings,
controllers, ordered verification, witnesses, version selection, partial
validity, deactivation, retained versions and copy comparison are implemented
in Ada. Cryptography binds directly to libsodium. A small C++17 helper uses
`std::to_chars` for shortest binary64 digits and applies JCS notation rules.
There is no dependency on another VH-Log implementation.

## Build and test

On macOS:

```sh
brew install libsodium
sh scripts/setup.sh  # Alire 2.1.1 and native GNAT 16.1.0
sh scripts/build.sh
sh scripts/test.sh
```

On Debian/Ubuntu Linux:

```sh
sudo apt-get update
sudo apt-get install build-essential curl unzip ca-certificates
sh scripts/setup.sh
sh scripts/build.sh
sh scripts/test.sh
```

The bootstrap pins Alire 2.1.1, GNAT native 16.1.0, and on Linux libsodium
1.0.22 (verified against its SHA-256 checksum, built into `tools/sodium`). It
supports aarch64 and x86_64 on both operating systems. A preinstalled GNAT and
system libsodium can also be used without running the bootstrap. The compiler
must support Ada 2022; the C++ library must support floating-point
`std::to_chars`. Build scripts find Alire's installed compiler automatically.
Apple Clang supplies the C++ helper on macOS; Linux uses `c++`.

The library test program checks known cryptographic answers, parser rejection,
canonical numbers, proof tampering, typed controller/resolver calls, historical
selection, partial validity, deactivation, nested allocation scopes, and trusted
copy extension. With Node available, `scripts/test.sh` also compares 5,006
finite binary64 values against ECMAScript's number serialization.

From the repository root:

```sh
node harness/run.ts --impl ada
node harness/run.ts --impl typescript --impl ada --suite cross
```

## Native library API

Packages:

- `JSON`: tagged JSON values, strict I-JSON parser, JCS canonicalization,
  object/array access, deep copies, and storage scopes.
- `Crypto`: base58btc, hexadecimal decoding, SHA-256/SHA-512, SHA-256 multihashes,
  constrained Ed25519 seed/public key/signature types and libsodium operations.
- `VH_Types`: typed controller requests/results and resolution selectors/options.
- `VH_Log`: SCID/entry hashes, Data Integrity signing/verification, create,
  update, witness and resolve operations.

```ada
with Ada.Text_IO;
with Ada.Strings.Unbounded;
with Crypto;
with JSON;
with VH_Log;
with VH_Types;

procedure Example is
   use Ada.Strings.Unbounded;
   Scope : JSON.Storage_Scope;
   Seed : constant Crypto.Hex_Seed := (others => '0');
   Request : VH_Types.Controller_Request;
   Generated : VH_Types.Generated_Log;
   Resolved : VH_Types.Resolution_Result;
begin
   Request.State := JSON.Parse ("{""id"":""example:{SCID}""}");
   Request.Version_Time := To_Unbounded_String ("2026-01-01T00:00:00Z");
   Request.Signers.Append (Seed);
   JSON.Put (Request.Parameters, "updateKeys", JSON.Arr);
   JSON.Add (JSON.Get (Request.Parameters, "updateKeys"),
             JSON.Str (Crypto.Multikey (Seed)));
   Generated := VH_Log.Create (Request);
   Resolved := VH_Log.Resolve
     (To_String (Generated.Content), "2026-01-02T00:00:00Z");
   if Resolved.Valid then
      Ada.Text_IO.Put_Line (JSON.Canonical (Resolved.State));
   end if;
end Example;
```

Update with `VH_Log.Update (Existing_Log, Request)`; empty `Request.Parameters`
means no parameter changes. To select a historical version, pass
`Options => (Selector => (By_Version_Number, 1), Min_Copies => 1)` with
`use VH_Types`. Resolution returns metadata and a structured error as JSON;
`First_Invalid_Version = 0` means no invalid suffix. A valid prefix can return
`Valid = True` while carrying an error describing later invalid entries.

The JSON-form overloads of `Create`, `Update` and `Resolve`, plus `Dispatch`,
accept the exact interop protocol request fields. `Sign` and `Verify` operate
on JSON documents; `Verify` checks the signature and proof format, while
`Resolve` also checks authorization. The `Witness` operation constructs a
proof over `{"versionId": ...}`. Resolution accepts supplied watcher copies;
it does not perform network retrieval.

Create a `JSON.Storage_Scope` before allocating JSON values. Its finalization
reclaims all JSON values allocated within the scope, including intermediate
values created by library operations. Nested scopes work, but JSON values must
not escape their allocating scope. The allocation registry is single-task;
applications using multiple Ada tasks must serialize library access. Without
a scope, values remain allocated for the process lifetime. Binary strings in
`Crypto` contain raw bytes; JSON strings contain validated UTF-8.

## JSON Lines driver

```sh
sh scripts/run.sh <<'JSON'
{"id":1,"op":"hash","input":{"data":"abc"}}
JSON
```

The driver reads bytes with POSIX `read`, splits only on LF, processes requests
in order, flushes each response, and exits successfully at EOF. Every request
gets a JSON response with the same `id`; driver exceptions set outer `ok` to
false. Invalid logs return outer `ok: true` with `result.valid: false` or a
partially valid resolution. Stdout contains JSON Lines only.

Verified locally on aarch64 macOS with GNAT 16.1.0, Apple Clang/libc++ and
libsodium 1.0.22: 257/257 shared checks, 60/60 TypeScript/Ada generation and
cross-resolution checks, 21 native library checks, and 5,006 numeric checks.
Linux bootstrap/build support is documented and pinned, but has not been
executed in this macOS environment. See `CLEAN-ROOM.md` for profile choices.
