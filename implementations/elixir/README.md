# VH-Log — Elixir

An Elixir implementation of [VH-Log](../../docs/profile.md) (Verifiable History
Log) following the `vh-log-interop-0` profile. It has no third-party
dependencies: JSON comes from Elixir's built-in `JSON` module (OTP `:json`),
and Ed25519 and SHA-256 come from `:crypto`. Base58btc and RFC 8785 JCS are
implemented in `lib/`.

Requires Elixir ≥ 1.18 (developed on 1.20 / OTP 29).

## Usage

```elixir
seed = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
key = VHLog.Multikey.from_seed(seed).multikey

{:ok, %{log: log, scid: scid}} =
  VHLog.create(
    state: %{"id" => "example:{SCID}"},
    parameters: %{"updateKeys" => [key]},
    version_time: "2026-01-01T00:00:00Z",
    signers: [seed]
  )

{:ok, %{log: log, version_id: v2}} =
  VHLog.update(log,
    state: %{"id" => "example:" <> scid, "name" => "renamed"},
    version_time: "2026-01-02T00:00:00Z",
    signers: [seed]
  )

{:ok, resolution} = VHLog.resolve(log, now: "2026-06-01T00:00:00Z")
resolution.state                       #=> %{"id" => "example:Qm…", "name" => "renamed"}
resolution.metadata["versionNumber"]   #=> 2

# Version selection, witnesses, copies and retained versionIds:
VHLog.resolve(log, now: "2026-06-01T00:00:00Z", version_number: 1)
VHLog.resolve(log, witness: [%{"versionId" => v2, "proof" => [VHLog.witness_proof(v2, seed)]}])
VHLog.resolve(log, copies: [%{"source" => "https://w1.example", "log" => log}], min_copies: 2)

# Failures are tagged tuples carrying a profile error code:
{:error, %VHLog.Error{code: :not_found}} = VHLog.resolve(log, version_number: 9)
```

When a later entry is invalid, resolution still succeeds with the valid prefix
and reports where the log breaks in `resolution.first_invalid_version` and
`resolution.error`.

### Modules

| Module | Purpose |
| --- | --- |
| `VHLog` | `create/1`, `update/2`, `witness_proof/2`, `verify/2`, `resolve/2` |
| `VHLog.Verifier` | Per-entry checks (profile §4) as a fold, then witness verification |
| `VHLog.Resolver` | Version selection, partial validity, copies, retained versionId |
| `VHLog.Parameters` | Parameter validation, inheritance and pre-rotation |
| `VHLog.Proof` | `eddsa-jcs-2022` create/verify |
| `VHLog.Log` | SCID, entry hash, sealing and serialisation (Log Controller) |
| `VHLog.JCS`, `VHLog.JSON` | RFC 8785 canonicalisation, JSON with double-only numbers |
| `VHLog.Base58`, `VHLog.Multikey`, `VHLog.Hash` | Encodings, Ed25519 keys, SHA-256 multihashes |
| `VHLog.Error` | The profile's error codes (`:entry_hash_mismatch` ↔ `"entry-hash-mismatch"`) |
| `VHLog.Driver` | The interop-protocol driver |

## Testing

```sh
mix test                      # unit tests, doctests, and every vector in ../../vectors
mix format --check-formatted
```

Interop harness, from the repository root:

```sh
node harness/run.ts --impl elixir
node harness/run.ts --impl typescript --impl elixir
```

The driver runs as `MIX_ENV=prod mix run --no-compile -e "VHLog.Driver.main()"`
(see `implementations.json`).
