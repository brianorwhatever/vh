# C NUL member-name validation (issue #8)

Tested implementation/test commit: `b1d8575` (2026-10-12).
Baseline full-driver reproduction: `93739b6125f01bc1a390cf16db6e94d657d7775b`
with the new regression tests applied, before the C fix.

Environment: macOS arm64, Apple clang 21.0.0 (clang-2100.3.34.2),
json-c 0.19, libsodium 1.0.22, Node v24.21.0, Python 3.12.15.
The driver was compiled with `sh implementations/c/build.sh` from its own
working directory (i.e. `cd implementations/c && sh build.sh`).

These are actual JSON Lines driver tests, exercising the exported
`vh_request` interface and its `jcs`, `create`, and `resolve` operations.
They are not json-c-only library probes. This does not establish an
end-to-end authorization bypass.

## Retained expected and actual results

For JCS input `{"a\u0000x":1,"a":2}`:

- Baseline C actual: success with `{"a":2}` (name silently lost).
- Fixed C expected and actual: `{"id":0,"ok":false,"error":"invalid-json"}`.
- TypeScript/Python expected and actual: success with
  `{"a":2,"a\u0000x":1}`.

For creation state `{id:"test:{SCID}", "a\0x":1, a:2}` (JS notation):

- Baseline C actual: success, emitted state only contained `id` and `a`;
  SCID was `QmSwq9RtQCLF424rTbyrfoz2EUbm7yEkBWEtwghjoYSgpy`.
- Fixed C expected and actual: `{"id":null,"ok":false,"error":"invalid-request"}`.
- TypeScript/Python expected and actual: both names retained, generated entry
  equal to the TypeScript reference.
- Resolution of the reference log: C expected and actual `ok:true`,
  `result.valid:false`, `result.error.code:"invalid-log"`;
  TypeScript/Python returned a valid result with the complete state.

The committed tests retain additional exact expectations for reversed prefix
collisions, empty-name collisions, distinct suffixes after NUL, nested objects,
whitespace before the colon, and repeated NUL names. String values containing
NUL and names containing literal `\\u0000` survive canonicalization round trips.
Creation with NUL in a state value matches the reference signed entry and
resolves successfully with the value intact. A valid request after a rejected
one succeeds in the same process.

## Commands and results

```sh
VH_TEST_IMPLS=c,typescript,python node --test harness/driver-regressions.test.ts
node harness/run.ts --impl c --impl typescript --impl python
```

Driver regressions: 18/18 passed (baseline C: two new tests failed).
Shared harness: 807/807 passed. Each of the three implementations passed
35 primitive, 158 resolution, 18 generation, 18 cross-resolution, and 40
external-reference checks.

The narrower C domain is documented in `docs/profile.md`. This deliberately
uses issue #8's rejection alternative: it prevents silent loss without claiming
full RFC 8785 support for NUL member names. TypeScript and Python preserve them.
