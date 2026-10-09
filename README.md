<img src="assets/icon.svg" width="64" height="64" alt="">

# vh

This repository has interoperable implementations of
[VH-Log](https://swcurran.github.io/VH-Log/next/), Stephen Curran's
**Verifiable History Log**, in four languages, plus a shared test suite that
checks the implementations against each other.

VH-Log is an append-only, hash-chained JSON Lines log of a versioned `state`
object:
- a self-certifying identifier (SCID) derived from the genesis entry;
- eddsa-jcs-2022 proofs from authorised update keys, with optional
  pre-rotation;
- optional witnesses and watchers.

It is the log under did:vh and (in future) did:webvh.

| Implementation | Path | Notes |
| --- | --- | --- |
| TypeScript | [`implementations/typescript`](implementations/typescript) | Reference implementation; generates the vectors. No runtime dependencies. |
| Rust | [`implementations/rust`](implementations/rust) | |
| Python | [`implementations/python`](implementations/python) | |
| Elixir | [`implementations/elixir`](implementations/elixir) | Resolution is a pure fold over immutable entries. Ed25519/SHA-256 come from OTP `:crypto`. Fits future witness/watcher services. |

Pinned spec: [`swcurran/VH-Log@f2f9fda`](https://github.com/swcurran/VH-Log/tree/f2f9fda)
([`spec.lock.json`](spec.lock.json)).

## How interoperability is tested

```
vectors/                    shared, language-neutral test data
  primitives.json           JCS, multihash, multikey, key hash, SCID, entry hash, proofs
  resolution/*.json         158 logs (valid and invalid), each with the expected result
  generation.json           scenarios each implementation must reproduce exactly
harness/run.ts              runs every implementation's driver against all of it
implementations.json        how to build and start each driver
```

Each implementation ships a **driver**: a process that speaks a small JSON
Lines protocol ([`docs/interop-protocol.md`](docs/interop-protocol.md)) on
stdin/stdout. The harness runs four suites against every driver:

1. **primitives** — byte-exact encodings, hashes and signatures.
2. **resolution** — the resolver's verdict on every vector log: validity, error
   code, failing version, state and metadata.
3. **generation** — Log Controller operations produce the same entries as the
   reference. Ed25519 and JCS are deterministic, so they must match exactly.
4. **cross** — every implementation resolves the logs and witness files that
   every other implementation generated.

```sh
node harness/run.ts                            # everything
node harness/run.ts --impl rust --impl python  # a subset
node harness/run.ts --suite resolution --group witnesses --verbose
```

### The interop profile

VH-Log leaves some choices to specialisations, and a few behaviours are open:
- how a proof names its key;
- what a witness signs;
- whether an invalid later entry voids the whole log;
- which error a resolver reports.

Implementations that are tested against each other must make the same choices.
[`docs/profile.md`](docs/profile.md) records those choices, including a shared
error-code list and check order. Issues found in the spec along the way are in
[`docs/spec-notes.md`](docs/spec-notes.md). Among them: the spec's only worked
entry-hash example doesn't reproduce.

## Development

Toolchains: Node ≥ 24, Rust stable, [uv](https://docs.astral.sh/uv/) (Python
3.12), Elixir ≥ 1.18 / OTP ≥ 27.

```sh
node tools/generate-vectors.ts   # regenerate vectors after changing the reference implementation
node harness/run.ts
```

When adding vectors, build each invalid log so that **exactly one** check
fails. The generator checks every vector against the reference resolver as it
writes it.

To add an implementation:
1. Write a driver for the protocol.
2. Add it to `implementations.json`.
3. Run the harness until it is green.

CI ([`.github/workflows/interop.yml`](.github/workflows/interop.yml)) runs each
implementation's own checks, verifies that the vectors are up to date, and
runs the full matrix.
