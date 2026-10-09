# vh-log (Python)

A Python implementation of [VH-Log](https://github.com/swcurran/VH-Log) (Verifiable History Log)
that follows this repository's interop profile ([`docs/profile.md`](../../docs/profile.md)): SHA-256
multihashes, Ed25519 `did:key` update keys and witnesses, and `eddsa-jcs-2022` proofs.

The only runtime dependency is [`cryptography`](https://cryptography.io/) (Ed25519). JCS (RFC 8785)
and base58btc are implemented in the package.

## Usage

```python
from vh_log import create_log, key_hash, resolve, signer_from_seed, update_log

seed = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"  # 32-byte Ed25519 seed, hex
next_seed = "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6"
key = signer_from_seed(seed).multikey  # "z6Mk..."
next_key = signer_from_seed(next_seed).multikey

created = create_log(
    state={"id": "example:{SCID}"},  # {SCID} is replaced by the log's SCID
    parameters={"updateKeys": [key], "nextKeyHashes": [key_hash(next_key)]},
    version_time="2026-01-01T00:00:00Z",
    signers=[seed],
)
updated = update_log(
    created.log,
    state={"id": f"example:{created.scid}", "name": "renamed"},
    parameters={"updateKeys": [next_key], "nextKeyHashes": []},
    version_time="2026-01-02T00:00:00Z",
    signers=[next_seed],
)

result = resolve(updated.log, now="2026-06-01T00:00:00Z")
if result["valid"]:
    print(result["state"], result["metadata"]["versionId"])
else:
    print(result["error"]["code"])  # one of vh_log.ErrorCode
```

`resolve` also accepts `witness=` (the parsed `vh-log-witness.json`), `options=` (`versionId`,
`versionTime`, `versionNumber`, `minCopies`), `copies=` (watcher copies to compare) and
`retained_version_id=`. Results use the JSON shape of the interop protocol. Verification failures are
returned in the result, not raised. `verify_log` returns the valid prefix as dataclasses, and
`VHLogError` carries an `ErrorCode` for lower-level use.

Numbers: as RFC 8785 requires, `parse_json` reads every JSON number as an IEEE-754 double, so
`123456789012345678` becomes `123456789012345680`. Integral values come back as `int`. Use
`parse_json` (not `json.loads`) on log text you hash yourself.

## Development

```sh
uv sync                     # create .venv with dev tools
uv run pytest               # unit tests + all shared vectors
uv run ruff check && uv run ruff format --check
uv run mypy                 # strict
```

Interop driver (JSON Lines on stdin/stdout, see [`docs/interop-protocol.md`](../../docs/interop-protocol.md)):

```sh
uv run python -m vh_log.driver
# from the repository root:
node harness/run.ts --impl python
```
