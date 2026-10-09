# vh-log (Rust)

A Rust implementation of VH-Log for the [interop profile](../../docs/profile.md):
JCS, base58btc/multihash/multikey, `eddsa-jcs-2022` proofs, the Log Controller
operations, log verification and resolution (version selection, partial
validity, witnesses, copy comparison and retained `versionId`s).

```rust
use serde_json::{json, Map};
use vh_log::{create_log, resolve, update_log, ResolveInput, ResolveResult, Signer};

let key = Signer::from_seed_hex(&"01".repeat(32))?;
let mut params = Map::new();
params.insert("updateKeys".into(), json!([key.multikey()]));

let created = create_log(json!({"id": "example:{SCID}"}), params, "2026-01-01T00:00:00Z", &[key.clone()]);
let updated = update_log(
    &created.log,
    json!({"id": format!("example:{}", created.scid), "name": "updated"}),
    Map::new(), // no parameter changes; use {"deactivated": true} to deactivate
    "2026-01-02T00:00:00Z",
    &[key],
)?;

let result = resolve(&ResolveInput {
    log: updated.log,
    now: "2026-06-01T00:00:00Z".into(),
    ..ResolveInput::default()
});
match result {
    ResolveResult::Valid(r) => println!("{:?} {}", r.state, r.metadata.version_id),
    ResolveResult::Invalid(e) => eprintln!("{} {}", e.code, e.message),
}
```

`ResolveInput` also takes a parsed witness file (`witness`), `options`
(`ResolveOptions`: `version_id` / `version_time` / `version_number` /
`min_copies`), watcher `copies` and a `retained_version_id`. Failures are
`VhLogError` values whose `code` is an `ErrorCode` from profile §6;
`ResolveResult::to_json()` gives the protocol's JSON form.

| Module | Contents |
| --- | --- |
| `jcs` | RFC 8785 canonicalisation (numbers as doubles, ECMAScript formatting, UTF-16 key order) |
| `encoding`, `hash` | base58btc, hex, Ed25519 multikey, SHA-256 multihash, key hashes |
| `proof` | `Signer` (Ed25519 from a 32-byte seed) and `eddsa-jcs-2022` proofs |
| `log` | `create_log`, `update_log`, `witness_proof`, SCID/entry hashes, `seal_genesis`/`seal_entry` |
| `verify` | `verify_log`: the per-entry checks of profile §4 and witness thresholds |
| `resolve` | `resolve`: version selection, partial validity, copy comparison |
| `src/bin/vh-log-driver.rs` | [Interop driver](../../docs/interop-protocol.md) |

Dependencies: `serde`/`serde_json` (with `float_roundtrip` so numbers parse
exactly as doubles), `ryu-js` (ECMAScript number formatting), `sha2`,
`ed25519-dalek`, `url` (WHATWG URL parsing for `watchers`).

## Testing

Rust is installed keg-only here, so put it on `PATH` first:

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
cargo test                     # unit tests + the shared vectors in ../../vectors
cargo clippy --all-targets && cargo fmt --check
cd ../.. && node harness/run.ts --impl rust                    # interop harness
node harness/run.ts --impl typescript --impl rust             # cross-resolution
```
