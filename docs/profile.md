# VH-Log Interop Profile (`vh-log-interop-0`)

VH-Log deliberately leaves some choices to a *specialisation* (identifier format,
witness identity, how errors are returned) and leaves a few behaviours
ambiguous. To test implementations against each other, every implementation in
this repository follows the choices below. Where a rule restates the spec, the
spec section is linked; where it is our own choice, it is marked **Profile**.

Pinned spec: [`swcurran/VH-Log@f2f9fda`](https://github.com/swcurran/VH-Log/blob/f2f9fda/spec/specification.md)
(see [`spec.lock.json`](../spec.lock.json)). Known spec issues are tracked in
[`spec-notes.md`](spec-notes.md).

## 1. Encodings

| Concept | Rule |
| --- | --- |
| JSON canonicalisation | RFC 8785 (JCS). |
| Hash | SHA-256 only (`vh-log:1.0`). Multihash = `0x12 0x20 ‖ digest` (34 bytes). |
| `base58btc(x)` | Bitcoin alphabet, **no** multibase prefix. A SHA-256 multihash therefore always starts with `Qm`. |
| SCID / entry hash | `base58btc(multihash(utf8(JCS(entry))))` |
| Pre-rotation key hash | `base58btc(multihash(utf8(multikey)))` — the multikey *string* is hashed. |
| Ed25519 multikey | `"z" + base58btc(0xed 0x01 ‖ pubkey32)` (starts `z6Mk`). |
| Test keys | Ed25519 private keys are given as a 32-byte **seed**, hex encoded (RFC 8032 §5.1.5). |

## 2. Entry proofs (`eddsa-jcs-2022`)

Each element of `proof` is a Data Integrity proof per
[`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022):

```json
{
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "verificationMethod": "did:key:z6Mk…#z6Mk…",
  "created": "2026-01-01T00:00:00Z",
  "proofPurpose": "assertionMethod",
  "proofValue": "z…"
}
```

- Signing input: `SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))`, where
  `proofConfig` is the proof without `proofValue`, and `document` is the entry
  without `proof`. Neither the entry nor the proof carries `@context`.
- `proofValue` = `"z" + base58btc(signature64)`.
- **Profile:** `verificationMethod` is `did:key:<multikey>#<multikey>`. The
  multikey after `#` MUST equal the part after `did:key:` and MUST appear
  verbatim in the active `updateKeys`. (The spec only says it "resolves to a
  multikey"; this is the did:webvh convention.)
- **Profile:** generators set `created` to the entry's `versionTime`, which makes
  generation deterministic. Verifiers accept any `created` or none.
- **Profile:** `proof` MUST be a non-empty array. **Every** proof in it MUST be
  valid and from an authorised key.
- Verifiers MUST reject a wrong or absent `type`, `cryptosuite` or `proofPurpose`,
  a malformed `proofValue`, or a bad signature.

## 3. Witnesses

- **Profile:** a witness `id` is `did:key:<ed25519 multikey>`. Its verification
  key is the multikey, so no external resolution is needed (spec: *Witness
  Identity and Key Format*).
- **Profile:** a witness signs, with `eddsa-jcs-2022`, the document
  `{"versionId": "<versionId>"}`. The proof's `verificationMethod` is
  `<id>#<multikey>`. In the witness file the proof is stored without the
  document (as in did:webvh).
- Witness file name: `vh-log-witness.json`. Log file name: `vh-log.jsonl`.
- **Which list applies to entry *k***:
  - If entry *k* sets `witness` and the active value before *k* was `{}`, then
    *k*'s new list applies to *k*.
  - Otherwise the list active **before** *k* applies, including when *k*
    replaces the list or sets it to `{}`. *k*'s own value takes effect from
    *k+1*.
  - If the list that applies to *k* is `{}`, *k* needs no witnessing.
- Entry *k* is witnessed when the number of **distinct** ids in *k*'s list, each
  with a valid proof over the `versionId` of entry *k* **or any later entry in
  the log**, is at least `threshold`. Proofs for `versionId`s not in the log are
  ignored. A proof that can't be attributed to an id in the list is ignored.
- Witness ids are compared byte-for-byte after Unicode NFC normalisation.

## 4. Resolution behaviour

Resolvers process entries in order. **Profile:** each entry is checked in this
order, and the first failing check gives the error code (§6):

1. A deactivating entry came earlier → `entry-after-deactivation`.
2. Structure → `invalid-entry`.
3. Parameters (*Read* step 1, plus the pre-rotation rule of step 7, which only
   concerns parameters) → `invalid-parameter`, `unsupported-log-version`,
   `prerotation-violation`.
4. Proofs (step 2): an empty `proof` array → `invalid-proof`. Then, for each
   proof in order: if `verificationMethod` isn't `did:key:<mk>#<mk>` →
   `invalid-proof`; if `<mk>` isn't in the active `updateKeys` →
   `unauthorized-key`; if `type`, `cryptosuite`, `proofPurpose`, `proofValue`
   or the signature is wrong → `invalid-proof`.
5. `versionId` (step 3) → `invalid-version-id`, `invalid-hash-algorithm`,
   `entry-hash-mismatch`.
6. `versionTime` (step 4) → `invalid-version-time`, `future-version-time`.
7. Entry 1 only: SCID (step 5) → `invalid-hash-algorithm`, `scid-mismatch`.

Witness verification runs only after every entry has passed the checks above,
as the spec requires. It can then move `firstInvalidVersion` earlier, to the
first entry that is not witnessed.

**Partial validity (Profile):**
- If entry 1 fails, resolution fails (`ok: false`).
- If a later entry *k* fails (including an unwitnessed one), entries `1..k-1`
  stay valid and the log is reported with `firstInvalidVersion: k` and the
  error.
- With no target version, the resolver returns the state of the last valid
  entry with an `invalid-entries` warning.
- If the target version is valid, it is returned (the spec says so even when
  later entries are invalid).
- If the target version is at or after *k*, resolution fails with the error
  that invalidated *k*.

**Deactivation (Profile):**
- With no target version, the deactivating entry's state is returned.
- With a target version, that version's state is returned.
- `deactivated` is `true` in every case.
- An entry after the deactivating entry fails with `entry-after-deactivation`.

**Time:** the request supplies `now`. The future tolerance is **300 s**:
`versionTime > now + 300s` fails with `future-version-time`.

**`versionTime` format:** `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS+00:00`,
with no fractional seconds. Every 4-digit year is valid, including 0000–0099.
The month must be 01–12, the day must exist in that month (proleptic Gregorian
calendar, so 29 February only in leap years), and the time must be 00:00:00–23:59:59
(no leap second 60, no 24:00). Comparisons use the instant, not the string.

**Log lines must be I-JSON-safe (Profile):** a line that contains a number too
large to be a finite double (e.g. `1e400`), or a string or key with a lone
surrogate escape (e.g. `"\ud800"`), fails with `invalid-log`. If a key is
duplicated, the **last** value wins, as in every mainstream JSON parser. The
vectors pin this behaviour, and producers MUST NOT emit duplicate keys.

**`watchers` URLs (Profile):** each must consist only of printable ASCII
(U+0021–U+007E), start with `https://` or `http://`, and have at least one
character before the next `/`, `?` or `#` (a non-empty authority). Nothing else
is checked. This is easy to implement the same way everywhere, which WHATWG URL
parsing is not. International hostnames must be punycode-encoded.

**Unknown parameters** are ignored (spec: *Specialisation-defined Parameters*).
Known parameters with wrong types or values fail with `invalid-parameter`.

**Multiple copies (Profile):** the harness has no network, so watcher copies are
passed in the request (`copies`). They are compared as described in
*Comparing Copies of a Log*.
- A copy "passes verification" only if **every** entry is valid and witnessed.
- The primary copy (`source: "primary"`) is tried first as the reference copy.
- If two verified copies diverge, resolution fails with `fork-detected` for every
  target version.

## 5. Generation (Log Controller) behaviour

- Field order in a serialised entry: `versionId, versionTime, parameters, state, proof`.
- Lines are compact JSON terminated by `\n`. Output is compared as parsed JSON,
  never as bytes, so whitespace and key order don't affect interop. Hashes and
  signatures depend only on JCS.
- `create` replaces `{SCID}` in `parameters` and `state` by text replacement on
  the serialised preliminary entry, as the spec says. If no `scid` parameter is
  given, `"scid": "{SCID}"` is added. `logVersion` defaults to `"vh-log:1.0"`.
- `update` with no parameter changes writes `"parameters": {}`.
- Generators **do not** validate input semantics beyond what they need to
  produce a well-formed entry. This is deliberate, so that invalid-log vectors
  can be produced from the same code.

## 6. Error codes

Every implementation reports failures with exactly these codes.

| Code | Meaning (spec step) |
| --- | --- |
| `invalid-log` | Empty log, or a line that is not a JSON object. |
| `invalid-entry` | Entry is missing, or has extra, top-level properties, or a property has the wrong JSON type. |
| `invalid-parameter` | A known parameter has the wrong type or value, `scid` is in a later entry, `null` is used, a witness config is malformed (bad threshold, duplicate ids, empty list), or a required first-entry parameter is missing. |
| `unsupported-log-version` | `logVersion` is unknown, missing from entry 1, or lowered. |
| `prerotation-violation` | Pre-rotation is active and `updateKeys` or `nextKeyHashes` is not explicit, or a key hash is not committed. |
| `invalid-proof` | Proof structure, type, cryptosuite, purpose, proofValue or signature is invalid. |
| `unauthorized-key` | Proof key is not in the active `updateKeys`. |
| `invalid-version-id` | Bad format, wrong version number, gap. |
| `invalid-hash-algorithm` | Entry hash or SCID is not a SHA-256 multihash. |
| `entry-hash-mismatch` | Recomputed entry hash differs. |
| `invalid-version-time` | Bad format, non-UTC, fractional seconds, not strictly increasing. |
| `future-version-time` | `versionTime` beyond the tolerance. |
| `scid-mismatch` | Recomputed SCID differs. |
| `entry-after-deactivation` | An entry follows a deactivating entry. |
| `witness-threshold-not-met` | Entry requires witnessing and the threshold is not met. |
| `invalid-witness-file` | Witness file is not a JSON array of `{versionId, proof[]}`. |
| `fork-detected` | Two verified copies diverge, or a retained `versionId` mismatches. |
| `min-copies-not-met` | Fewer than `minCopies` copies are `current` or `behind`. |
| `not-found` | Target version not in the log. |
| `invalid-option` | Unknown option, or more than one version selector. |

Vectors for invalid logs are built so that **exactly one** check fails, which
makes the expected code unambiguous. If a vector can legitimately fail in more
than one way, it lists the alternatives in `error.oneOf`.
