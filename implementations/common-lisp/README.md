# vh-log for Common Lisp

A [VH-Log](https://swcurran.github.io/VH-Log/next/) library for SBCL: JSON and
RFC 8785 canonicalisation, base58btc / multihash / multikey encodings,
eddsa-jcs-2022 proofs, the Log Controller operations (create, update,
witness), and a resolver covering witnesses, multiple copies, retained
`versionId`s and the check order and error codes of the
[interop profile](../../docs/profile.md).

**Clean-room.** This implementation was written only from the pinned spec
(`swcurran/VH-Log@f2f9fda`), [`docs/`](../../docs), the shared
[`vectors/`](../../vectors), [`harness/run.ts`](../../harness/run.ts) and
library documentation, without reading any other implementation in this
repository. Where those sources were silent, the choices made are listed in
[`CLEAN-ROOM.md`](CLEAN-ROOM.md).

## Setup

You need SBCL (developed with 2.6.9) and git.

```sh
brew install sbcl                 # macOS
sudo apt-get install -y sbcl git  # Debian / Ubuntu

./scripts/build.sh   # fetches pinned deps into deps/, builds bin/vh-log-driver
./scripts/test.sh    # unit tests + every shared vector, through the library
```

`scripts/fetch-deps.sh` clones each dependency at an exact commit, so builds are
reproducible and need no Quicklisp. The only direct dependency is
[Ironclad](https://github.com/sharplispers/ironclad) v0.61 (SHA-256, SHA-512,
Ed25519); only those three subsystems are loaded. The other five
(bordeaux-threads, alexandria, global-vars, trivial-features,
trivial-garbage) are Ironclad's own dependencies. Compiled files go to
`deps/.fasl/`, not `~/.cache`.

From the repository root, `node harness/run.ts --impl common-lisp` builds the
driver and runs the interop suites against it.

## Usage

```lisp
(asdf:load-system "vh-log")
(use-package :vh-log)

(let* ((key (make-signer "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"))
       (log (create-log :state (make-json "id" "example:{SCID}")
                        :parameters (make-json "updateKeys" (vector (signer-multikey key)))
                        :version-time "2026-01-01T00:00:00Z"
                        :signers (list key)))
       (log (update-log log :state (make-json "v" 2)
                            :version-time "2026-01-02T00:00:00Z"
                            :signers (list key)))
       (result (resolve log :now "2026-06-01T00:00:00Z")))
  (values (resolution-valid-p result)
          (to-json (resolution-state result))
          (jget (resolution-metadata result) "versionId")))
```

JSON values are plain Lisp data: objects are `json-object`s (ordered, built
with `make-json`, read with `jget`), arrays are vectors, numbers are
double-floats, and `true`/`false`/`null` are `:true`/`:false`/`:null`.

| Area | Functions |
| --- | --- |
| JSON | `parse-json`, `to-json`, `canonicalize` (JCS), `make-json`, `jget`, `jwith`, `jwithout` |
| Encodings | `base58-encode`/`-decode`, `multihash`, `decode-multihash`, `hash-string`, `ed25519-multikey`, `key-hash` |
| Proofs | `make-signer`, `sign-document`, `verify-proof` |
| Log Controller | `create-log`, `update-log`, `witness-proof`, `compute-scid`, `entry-hash` |
| Resolver | `resolve` → `resolution` (`resolution-valid-p`, `-state`, `-metadata`, `-error`, `-first-invalid-version`), `resolution-to-json` |

`resolve` takes the log text and `:now`, plus optionally `:witness` (the
parsed witness file), `:options` (a JSON object: `versionId`, `versionTime`,
`versionNumber`, `minCopies`), `:copies` (plists `(:source s :log text
[:witness w])` or `(:source s :unavailable reason)`) and
`:retained-version-id`. Failures are `log-error` conditions carrying the
profile's error code and version.

## Layout

| File | Contents |
| --- | --- |
| `src/json.lisp` | I-JSON parser, exact decimal ↔ double conversion, ECMAScript number formatting, JCS |
| `src/encoding.lisp` | hex, base58btc, multihash, Ed25519 multikeys |
| `src/time.lisp` | `versionTime` parsing (proleptic Gregorian, years 0000–9999) |
| `src/proof.lisp` | eddsa-jcs-2022 signing and verification with did:key methods |
| `src/log.lisp` | SCID, entry hash, create / update / witness |
| `src/resolve.lisp` | per-entry checks in profile order, witnesses, copy comparison, version selection |
| `src/driver.lisp` | JSON Lines driver ([protocol](../../docs/interop-protocol.md)) |
| `tests/` | unit tests and the shared vectors run through the library (no test framework dependency) |

## Notes

- **Numbers.** Every JSON number is parsed to the nearest double with exact
  integer arithmetic (round half to even, subnormals included), and printed
  with ECMAScript's shortest-round-trip rule, also computed exactly. A
  property test round-trips 20,000 random doubles. Numbers that overflow a
  double, and lone surrogate escapes, make a log line `invalid-log`.
- **Crypto.** SHA-2 and Ed25519 come from Ironclad, a maintained pure-Lisp
  library. Ironclad has not had a formal audit, and its Ed25519 uses generic
  bignum arithmetic, so it is not constant-time. That is fine for
  verification and for the test keys used here. A production Log Controller
  or witness that signs with secret keys should consider a constant-time
  backend. No cryptography is implemented in this library itself.
- The driver is an SBCL executable image (about 40 MB) saved by
  `scripts/build.lisp`, so it starts in milliseconds.
