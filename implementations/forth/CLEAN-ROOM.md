# Clean-room notes

This implementation was written from:

- `swcurran/VH-Log@f2f9fda`, `spec/specification.md` (the revision in `spec.lock.json`);
- `docs/profile.md` and `docs/interop-protocol.md`;
- the shared primitive, generation, resolution, and external vectors;
- the repository README, driver registry, CI workflow, and harness contract.

No other language's implementation source was read or translated. The shared
harness imports its existing canonicalizer as part of running tests; the Forth
driver neither imports nor invokes that implementation. Native dependencies are
general-purpose JSON, Unicode, numeric-formatting, and cryptographic libraries.

The profile resolves the choices needed to interoperate: exact error ordering,
previous-versus-current update keys, future-time tolerance, witness activation,
partial validity, and version-selection behavior. No new profile changes were
needed to pass the shared vectors.

Two details deserve explicit attention in independent implementations:

1. Witness verification runs only after the complete entry-validation pass
   succeeds. An invalid later entry preserves the preceding entry-valid prefix
   without running the witness pass. The `witness-checked-after-entries` vector
   pins this ordering; applying witness checks opportunistically changes the
   reported error and valid prefix.
2. Copy comparison deliberately trusts a matching boundary `versionId` without
   rechecking the matching prefix's contents. This includes a copy whose body
   has been altered behind unchanged version IDs. A longer matching copy must
   extend the already verified state; it must not replace that state with its
   unverified prefix. A separate driver regression exercises historical
   selection after extending such a copy.

These are observations about the specified interoperability behavior, not
additional validation rules introduced by this implementation.
