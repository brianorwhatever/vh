# Independent Ed25519 conformance sources

These inputs are independent of `tools/generate-vectors.ts` and of the
TypeScript resolver. Expected results are specified by profile §2.

- `cctv.json` is the unmodified `ed25519/ed25519vectors.json` from
  [C2SP/CCTV at 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7](https://github.com/C2SP/CCTV/tree/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/ed25519).
  Its adjacent README defines the flags and enumerates all 14 encodings of
  the eight small-order points. The BSD license is retained in `CCTV-LICENSE`.
  Reject a vector if any of `low_order_A`, `low_order_R`, `non_canonical_A`,
  `non_canonical_R`, or `low_order_residue` is set; accept the rest. In
  particular, `low_order_component_A/R` alone are NOT rejection flags.
- `wycheproof.json` is the unmodified `testvectors_v1/ed25519_test.json` from
  [C2SP/wycheproof at 7a325932231bd7a724c791c8b0d65ea4d6d2f435](https://github.com/C2SP/wycheproof/blob/7a325932231bd7a724c791c8b0d65ea4d6d2f435/testvectors_v1/ed25519_test.json).
  Use its `valid` / `invalid` outcomes directly. Its Apache 2.0 license is
  retained in `WYCHEPROOF-LICENSE`. This includes ordinary valid controls,
  malleable scalars, truncation, garbage suffixes and invalid encodings.
- `boundaries.json` is produced by `python3 tools/ed25519-fixtures.py`, using
  only Python's standard library. It constructs VH-Log hashes and signing
  inputs independently, using ASCII-only JCS and public known scalars. The
  low-order encodings come from CCTV, not our verifiers. Rejection expectations
  are fixed policy decisions, never the output of a resolver. Mixed-order
  expectations additionally check the exact equation with independent RFC
  8032 affine Edwards arithmetic. These are public test scalars, not secrets.

Run the raw corpora through the TypeScript and Python library test suites.
After building the registered drivers, `node --test harness/ed25519.test.ts`
runs the independent proof and full resolver fixtures through all 24 drivers.
`VH_TEST_IMPLS=python,typescript` selects a subset. The proof primitive calls
the same library verifier used by entry and witness verification; it does not
bypass the library in the driver. The fixture generator is test-only and is
not suitable for use as a production cryptographic implementation.
