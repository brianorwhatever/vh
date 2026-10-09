# vh-log (TypeScript)

This is the reference implementation of VH-Log for the
[interop profile](../../docs/profile.md). It has no runtime dependencies: Node 24's
`node:crypto` provides Ed25519 and SHA-256, and Node runs the `.ts` sources
directly through type stripping, so there is no build step.

```ts
import { createLog, keyHash, resolve, signerFromSeed, updateLog } from "vh-log";

const k1 = "…32-byte Ed25519 seed, hex…";
const { log, scid } = createLog({
  state: { id: "example:{SCID}" },
  parameters: { updateKeys: [signerFromSeed(k1).multikey] },
  versionTime: "2026-01-01T00:00:00Z",
  signers: [k1],
});

const next = updateLog({
  log,
  state: { id: `example:${scid}`, name: "updated" },
  versionTime: "2026-01-02T00:00:00Z",
  signers: [k1],
});

const result = resolve({ log: next.log, now: new Date().toISOString().replace(/\.\d+Z$/, "Z") });
if (result.valid) console.log(result.state, result.metadata.versionId);
else console.error(result.error.code, result.error.message);
```

| Module | Contents |
| --- | --- |
| `jcs.ts` | RFC 8785 canonicalisation |
| `encoding.ts`, `hash.ts` | base58btc, multikey, SHA-256 multihash |
| `proof.ts`, `ed25519.ts` | eddsa-jcs-2022 Data Integrity proofs |
| `log.ts` | Log Controller operations: create, update, witness proofs, and the low-level `sealGenesis`/`sealEntry` used to build test vectors |
| `verify.ts` | Per-entry verification and witness thresholds |
| `resolve.ts` | Resolution: version selection, partial validity, copy comparison |
| `driver.ts` | [Interop driver](../../docs/interop-protocol.md) |

```sh
npm install        # dev dependencies only (typescript, @types/node)
npm test           # unit tests
npx tsc --noEmit   # typecheck
```

The shared vectors in `/vectors` are generated from this implementation by
`node tools/generate-vectors.ts`.
