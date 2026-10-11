# OCaml VH-Log

Independent clean-room OCaml implementation of the pinned VH-Log specification
and `vh-log-interop-0` profile. The library implements strict JSON/JCS, base58btc,
SHA-256/SHA-512 multihashes, Ed25519 multikeys and proofs, deterministic controller
operations, witness rotation, resolution with valid prefixes, version selection,
deactivation, supplied-copy comparison, forks and retained versions.

All VH-Log behavior is implemented in OCaml. `src/native.cpp` binds OpenSSL's
maintained SHA/Ed25519 primitives and C++17's shortest binary64 conversion.
It does not contain log processing. There are no runtime OCaml package dependencies.

## Build and test

On macOS:

```sh
brew install ocaml openssl@3
sh scripts/build.sh
sh scripts/test.sh
sh scripts/run.sh
```

The tested toolchain is OCaml 5.5.1, Apple Clang 21.0.0 and OpenSSL 3.6.5,
with macOS ARM64. `OCAMLC`, `OCAMLOPT`, `CXX` and `OPENSSL_PREFIX` can override
compiler/dependency discovery. Linux builds require a C++17 compiler with floating
`std::to_chars` support (GCC 12 or later), OpenSSL 3.x, and OCaml 5.2 or later.

For a pinned Linux toolchain, install the prerequisites and run:

```sh
sudo apt-get install opam curl build-essential pkg-config perl
sh scripts/setup-linux.sh
opam exec -- sh scripts/test.sh
```

The setup script pins OCaml **5.5.1** and builds OpenSSL **3.6.5** locally from
its SHA-256-checked source archive. Compiler tools and operating-system build
packages come from the host. Setup/build artifacts remain in this directory's
ignored `_opam`, `_deps` and `_build` folders. The pinned Linux setup is supplied
but has not been executed on a Linux host in this clean room.

From the repository root:

```sh
node harness/run.ts --impl ocaml
node harness/run.ts --impl typescript --impl ocaml --suite cross
```

The first command passes all **257** checks. The second passes **60** checks,
including generation and both directions of cross-resolution for six scenarios.
`sh scripts/test.sh` checks independent RFC 8032/SHA-512 known answers, strict
parsing, base58 byte preservation, generation/resolution, older deactivated
versions, partial validity, matching-copy extension, forks and proof tampering.

## Library API

The public interface is `src/vh_log.mli`. `Json.t`, version selectors and resolution
outcomes are algebraic types. `create_entry`, `update_entry`, `resolve_log`,
`Crypto.sign_result`, `Crypto.multikey_result`, `Crypto.witness` and `Json.parse_result`
return OCaml `result` values. Protocol errors have stable profile codes, a version
number when relevant, and fork evidence when relevant. The `Json` and `Crypto`
modules also expose lower-level helpers that raise exceptions for malformed inputs.

```ocaml
let require = function Ok value -> value | Error message -> failwith message

(* RFC 8032 public test seed; use your own securely managed seed in an application. *)
let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
let key = require (Crypto.multikey_result seed)

let initial : Vh_log.controller_input = {
  state = Json.Object ["id", Json.String "example:{SCID}"];
  parameters = Json.Object ["updateKeys", Json.Array [Json.String key]];
  version_time = "2026-01-01T00:00:00Z";
  signers = [seed];
}

let created = require (Vh_log.create_entry initial)
let updated = require (Vh_log.update_entry ~log:created.log {
  initial with
  state = Json.Object ["id", Json.String ("example:" ^ Option.get created.scid);
                       "label", Json.String "updated"];
  parameters = Json.Object [];
  version_time = "2026-01-02T00:00:00Z";
})

let request : Vh_log.resolution_request = {
  log = updated.log;
  witness = None;
  now = "2026-01-03T00:00:00Z";
  selector = Vh_log.Latest;
  min_copies = 1;
  copies = [];
  retained_version_id = None;
}

let outcome = require (Vh_log.resolve_log request)
let () = match outcome with
  | Vh_log.Resolved value -> print_endline (Json.serialize value.state)
  | Vh_log.Rejected error -> prerr_endline error.code
```

Compile an application after building the library:

```sh
ocamlopt -I _build _build/vh_log.cmxa example.ml -o example
```

The archive records native linker dependencies; keep `_build/libvh_native.a`
and the selected OpenSSL installation available when linking applications.

Select older versions with `Version_id id`, `Version_time time`, or
`Version_number number`. A `Resolved` result can still have `error = Some error`
and `first_invalid_version = Some number` when it returns a valid prefix.
A valid target before that prefix boundary remains resolvable. Forks reject all targets.

Create a witness proof with:

```ocaml
let proof = require (Crypto.witness ~version_id:updated.version_id ~seed ())
let witness_file = Json.Array [Json.Object [
  "versionId", Json.String updated.version_id;
  "proof", Json.Array [proof];
]]
```

Witness keys need to be listed in the log's `witness` configuration. Set
`request.witness = Some witness_file` when resolving. `None` means absent;
`Some Json.Null` means an explicitly malformed witness file.

For offline copy comparison, provide `supplied_copy` records in `request.copies`.
`log = None` represents an unavailable copy. Set `min_copies` and
`retained_version_id` to enable the corresponding integrity checks. This profile
accepts supplied copies rather than fetching watcher URLs. Network retrieval,
`checkWatchers` and `extraWatchers` are outside the driver's supported options.

`Json.canonicalize` uses binary64 numbers, ECMAScript-style shortest formatting,
and UTF-16 key order. `Crypto.hash` produces the profile SHA-256 base58 multihash;
`Crypto.hash512` is available as a primitive, but log resolution accepts SHA-256 only.
`Vh_log.scid` and `Vh_log.entry_hash` operate on JSON entry objects.

## JSON Lines driver

`sh scripts/run.sh` reads one request per LF-delimited line, processes requests in
order, and writes exactly one compact JSON response per request to stdout.
It supports every operation listed in `docs/interop-protocol.md` through
`Vh_log.perform`. Diagnostics belong on stderr; EOF exits successfully.

```json
{"id":1,"op":"jcs","input":{"text":"{\"b\":1,\"a\":2}"}}
```

See `CLEAN-ROOM.md` for the independence record, interpretation choices and limits.
