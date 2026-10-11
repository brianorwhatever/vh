# VH-Log for Gleam

Native Gleam controller and resolver for the complete `vh-log-interop-0`
profile, targeting Erlang/OTP. JSON values use a typed sum type and all protocol
checks return explicit results. An Erlang FFI module supplies OTP JSON parsing,
SHA-256/Ed25519, base58, calendar validation, and scalar JSON formatting.
Canonicalization traversal and all controller/resolver rules are in Gleam.

Requires Gleam 1.19 or newer and Erlang/OTP 28 or newer. Dependencies are pinned
in `manifest.toml`. The JavaScript target is not supported.

```sh
cd implementations/gleam
gleam deps download
gleam format --check src
gleam build --warnings-as-errors
sh run.sh
# From the repository root:
node harness/run.ts --impl gleam --impl typescript
VH_TEST_IMPLS=gleam node --test harness/driver-regressions.test.ts
```

Add this directory as a local dependency and use `vh_log` and `json_value`:

```gleam
import json_value as json
import vh_log

pub fn resolve_text(log: String) -> json.Json {
  vh_log.resolve(json.object([
    #("log", json.Str(log)),
    #("now", json.Str("2026-01-02T00:00:00Z")),
  ]))
}
```

`create`, `update`, `sign`, `verify`, `scid`, and `entry_hash` are also available.
`dispatch` returns `Result(Json, String)` for the
[driver operations](../../docs/interop-protocol.md). `json_value.parse` rejects
unsafe JSON and explicitly applies last-value-wins handling to duplicate keys.
Resolution includes witnesses, key rotation, partial validity, selectors, and
copy/fork metadata. Controller calls expect well-typed input; the driver catches
invalid-request exceptions without terminating the stream.
