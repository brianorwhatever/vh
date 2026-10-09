# Interop Protocol

Every implementation ships a **driver**: a long-running process that reads
requests from stdin and writes responses to stdout, one compact JSON object per
line (JSON Lines). The harness starts each driver once and streams every test
through it. Drivers are registered in [`implementations.json`](../implementations.json).

```
→ {"id": 1, "op": "jcs", "input": {"text": "{\"b\": 1, \"a\": [true, null]}"}}
← {"id": 1, "ok": true, "result": {"output": "{\"a\":[true,null],\"b\":1}"}}
→ {"id": 2, "op": "resolve", "input": {"log": "…", "now": "2026-01-01T00:00:00Z"}}
← {"id": 2, "ok": true, "result": {…}}
```

- Messages are separated by `\n` **only**. JSON strings may contain unescaped
  U+2028/U+2029 (and the vectors do), so don't use a reader that also splits on
  those characters or on `\r` (Node's `readline` does).
- `id` is echoed back. Requests are handled strictly in order.
- `ok: false` means the **driver** failed (unknown op, malformed request, or a
  bug): `{"id": n, "ok": false, "error": "message"}`. A resolution that
  *verifies* a log and finds it invalid is still `ok: true` at this level. The
  verification outcome is inside `result`.
- Drivers MUST NOT write anything else to stdout. Logs go to stderr.
- On EOF the driver exits with status 0.

**Numbers.** RFC 8785 treats every JSON number as an IEEE-754 double.
Libraries MUST parse numbers in log lines that way, so `123456789012345678`
canonicalises to `123456789012345680` and `1.0` to `1`. Languages with
arbitrary-precision integers (Python, Elixir) need care here. Vectors cover it.

Byte strings are hex. Keys are 32-byte Ed25519 seeds in hex (see
[profile §1](profile.md#1-encodings)).

## Primitive operations

| op | input | result |
| --- | --- | --- |
| `jcs` | `{"text": "<raw JSON text>"}` | `{"output": "<canonical string>"}` — the driver parses `text` with the library's own JSON parser |
| `hash` | `{"data": "<utf-8 string>"}` | `{"output": "<base58btc sha256 multihash>"}` |
| `multikey` | `{"seed": "<hex>"}` | `{"multikey": "z6Mk…"}` |
| `key-hash` | `{"multikey": "z6Mk…"}` | `{"output": "Qm…"}` |
| `scid` | `{"entry": <preliminary entry with {SCID} placeholders>}` | `{"scid": "Qm…"}` |
| `entry-hash` | `{"entry": <entry, proof optional>, "previousVersionId": "…"}` | `{"hash": "Qm…"}` |
| `sign` | `{"document": {…}, "seed": "<hex>", "verificationMethod"?: "…", "created"?: "…"}` | `{"proof": {…}}` |
| `verify` | `{"document": {…}, "proof": {…}}` | `{"valid": bool}` |

`sign` defaults `verificationMethod` to `did:key:<mk>#<mk>` and omits
`created` if absent. `verify` checks the eddsa-jcs-2022 signature only: the
`verificationMethod` must be in `did:key:<mk>#<mk>` form, and it does no
authorisation check.

## Log Controller operations

```jsonc
// create
{"op": "create", "input": {
  "state": {"id": "example:{SCID}"},
  "parameters": {"updateKeys": ["z6Mk…"], "nextKeyHashes": ["Qm…"]}, // scid/logVersion added if absent
  "versionTime": "2026-01-01T00:00:00Z",
  "signers": ["<seed hex>"]              // one proof per signer, in order
}}
→ {"log": "<jsonl text>", "scid": "Qm…", "versionId": "1-Qm…"}

// update (also used for deactivate: parameters {"deactivated": true})
{"op": "update", "input": {
  "log": "<jsonl text>",
  "state": {…},
  "parameters": {},
  "versionTime": "…",
  "signers": ["<seed hex>"]
}}
→ {"log": "<jsonl text with the new line appended>", "versionId": "2-Qm…"}

// witness: one witness proof for a versionId
{"op": "witness", "input": {"versionId": "2-Qm…", "seed": "<hex>", "created"?: "…"}}
→ {"proof": {…}}
```

Generators don't validate semantics (see [profile §5](profile.md#5-generation-log-controller-behaviour)).
`update` must, however, compute the hash chain from the last line of `log`.

## Resolve

```jsonc
{"op": "resolve", "input": {
  "log": "<jsonl text>",
  "witness"?: <witness file JSON array>,
  "now": "2026-06-01T00:00:00Z",
  "options"?: {
    "versionId"?: "…", "versionTime"?: "…", "versionNumber"?: 3,
    "minCopies"?: 1
  },
  "copies"?: [{"source": "https://w1.example", "log": "…", "witness"?: […]}
              | {"source": "https://w2.example", "unavailable": "timeout"}],
  "retainedVersionId"?: "4-Qm…"
}}
```

On success:

```jsonc
{"valid": true,
 "state": {…},
 "metadata": {
   "versionId": "…", "versionTime": "…", "versionNumber": 3,
   "created": "…", "updated": "…", "scid": "…",
   "deactivated": false, "ttl": 3600,
   "witness": {…} | null,      // active witness config at last valid entry, null if {}
   "watchers": […],
   "updateKeys": […], "nextKeyHashes": […],  // active at the resolved entry
   "copies"?: [{"source": "…", "versionId"?: "…", "status": "current|behind|invalid|unavailable"}],
   "warnings": [{"code": "invalid-entries", "source"?: "…", "message": "…"}]
 },
 "firstInvalidVersion": null | 5,
 "error": null | {"code": "entry-hash-mismatch", "version": 5, "message": "…"}}
```

On failure:

```jsonc
{"valid": false,
 "error": {"code": "scid-mismatch", "version": 1, "message": "…"}}
```

- Omitting `witness` means no witness file was found. An explicit `"witness": null`
  is a malformed witness file (`invalid-witness-file` if any entry needs
  witnessing).
- `firstInvalidVersion`/`error` describe partial validity of the reference copy
  ([profile §4](profile.md#4-resolution-behaviour)).
- For `fork-detected`, `error` also has `"fork": {"version": k, "copies": [{"source", "versionId"}]}`.
  If a retained `versionId` is involved, one item is `{"source": "retained", …}`.
- `updated` is the `versionTime` of the last valid entry.
- `metadata.updateKeys`/`nextKeyHashes` are extensions for testing. Hash
  inputs are never computed from them.

## Driver discovery

```json
{ "name": "typescript", "cwd": "implementations/typescript", "command": ["node", "src/driver.ts"] }
```

The harness runs `command` in `cwd`, with `PATH` extended by `env.PATH_PREPEND`
if that is set.
