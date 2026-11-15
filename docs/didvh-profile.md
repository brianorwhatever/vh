# did:vh Interop Profile (`didvh-interop-0`)

[did:vh](https://identity.foundation/didvh/) is a DID method derived from
did:webvh, with the location removed from the DID: a did:vh DID is
`did:vh:<SCID>`, and the client passes the DID log to the resolver. This
profile pins the choices every did:vh library in this repository makes, so
that they can be tested against each other.

Pinned spec: [`decentralized-identity/didvh@cc2eff6`](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md)
(v0.1 Editors Draft; see [`spec.lock.json`](../spec.lock.json)). Spec issues
found while writing this profile are in [`spec-notes.md`](spec-notes.md#didvh).
Where a rule restates the spec, the spec is linked; **Profile** marks our own
choices.

## 1. The log is VH-Log with a specialisation

did:vh and VH-Log both come from did:webvh. The DID log format, SCID, entry
hash, proofs, key authorisation, pre-rotation, witnesses and witness proofs
file are the same in all three. So each library here verifies a did:vh log
with its VH-Log code, as pinned by [`profile.md`](profile.md)
(`vh-log-interop-0`), including the Ed25519 acceptance rules, version
selection and partial validity. It passes a *specialisation* that sets the
following:

| | VH-Log | did:vh |
| --- | --- | --- |
| Version parameter | `logVersion` | `method` |
| Accepted values | `vh-log:1.0` | `did:vh:1.0` |
| Version syntax | none | `did:vh:<major>.<minor>`, each a non-negative integer with no leading zeros |
| Unknown parameters | ignored | **rejected** (`invalid-parameter`): the set is closed |
| State check | none | `state.id` (§2) |

**`method`** ([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#didvh-did-method-parameters)):

- A missing (in entry 1) or malformed `method`, such as `did:webvh:1.0`,
  `did:vh:01.0` or a non-string, fails the entry with `invalid-parameter`.
- A well-formed value other than `did:vh:1.0`, such as `did:vh:1.1`, makes the
  entry *unsupported*. It fails with `unsupported-log-version`, which did:vh
  reports as `featureNotSupported` (§5).
- `method` may appear in later entries, under the same rules as `logVersion`.

**Check order.** The did:vh rules slot into `profile.md` §4 as follows:

- In check 3 (parameters), the closed-set check runs first, right after the
  null check. So `logVersion` or `portable` fails with `invalid-parameter`.
- A new **check 8**, after the SCID check, runs on every entry: the state
  check (§2). It fails with the VH-Log error code `invalid-state`.

The spec lists the per-entry checks in a different order. All of them give
`invalidDid`, so the order only changes which VH-Log code appears in
`problemDetails.vhLog`.

The did:vh parameter set is `method`, `scid`, `updateKeys`, `nextKeyHashes`,
`witness`, `watchers`, `deactivated` and `ttl`. Witness ids are `did:key`
DIDs, which `profile.md` §3 already requires.

## 2. The DID and the DID document

- A did:vh DID is `did:vh:` followed by exactly 46 base58btc characters
  ([ABNF](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#method-specific-identifier)).
  The method name is lowercase only. Anything else is `invalidDid`.
- **State check (check 8).** Every entry's `state.id` MUST be exactly
  `did:vh:<SCID>`, where `<SCID>` is the log's `scid` parameter. When
  resolving a DID, the log's SCID MUST also equal the DID's. A mismatch of
  either kind fails that entry with `invalid-state`. So a valid log for a
  different DID fails at entry 1, and a later entry that changes `state.id`
  invalidates that entry and everything after it.
- **Profile:** nothing else in the DID document is validated. It is a JSON
  object with the right `id`.
- **Create.** The genesis DID document uses `did:vh:{SCID}` wherever it refers
  to the DID. Generators add `"method": "did:vh:1.0"` and `"scid": "{SCID}"` to
  the parameters if they are absent, after the caller's own parameters
  (`method` first, then `scid`). As in `profile.md` §5, they do not validate
  their input.

## 3. References

### 3.1 `srcLog` and `srcWitness`

These resolution options each name a **file**
([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#the-srclog-and-srcwitness-options)).
Libraries expose a check that returns the reference's kind or fails with
`invalidOptions`:

1. **Profile:** the value MUST be a string of printable ASCII
   (U+0021–U+007E). In particular, an internationalised host MUST already be
   in A-label (punycode) form. The spec instead requires the resolver to
   convert it, which would need an IDNA2008 library in every language (see
   `spec-notes.md`).
2. It MUST start with a scheme, `[A-Za-z][A-Za-z0-9+.-]*:`, compared
   case-insensitively.
3. It MUST NOT contain `#` (no fragment), whatever the scheme.
4. **`https` and `http`.** After the scheme comes `//` and an authority, which
   runs to the first `/` or `?`, or the end. The path runs from there to the
   first `?`. A query is allowed, and nothing in it is checked.
   - **Profile:** the authority MUST NOT contain `@`.
   - Host and port: an authority starting with `[` is an IP literal running to
     `]`; otherwise the host runs to the first `:`. A port is 1–5 digits with
     value ≤ 65535. The host is compared in lowercase.
   - `https` (kind `web`): the host MUST be a domain name. That means an
     optional trailing `.`, then 1–253 characters of dot-separated labels.
     Each label is 1–63 characters of `a-z`, `0-9` and `-`, and doesn't start
     or end with `-`. The last label MUST NOT be all digits. IP literals are
     not domain names.
   - `http` (kind `loopback`): the host MUST be `localhost`, `[::1]`, or an
     IPv4 dotted quad with first octet 127 (each octet decimal 0–255, with no
     leading zeros).
   - The path MUST be non-empty.
   - Each path segment (between `/`s) is percent-decoded as UTF-8. A
     malformed escape or invalid UTF-8 is invalid. The decoded segment MUST
     NOT be `.` or `..` and MUST NOT contain `/`, `\` or NUL. Empty segments
     and whitespace are allowed.
5. **`file` (kind `file`).** `file:///<path>`, `file://localhost/<path>`
   (host compared case-insensitively) or `file:/<path>`. Any other host is
   invalid, as are a relative path and a query. Segments are checked as in 4.
6. **Any other scheme (kind `other`).** Anything after the scheme's `:`,
   without a fragment.

### 3.2 The `src` DID URL parameter

`src` names the location holding both files, and is used only in DID URLs
([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#the-src-did-url-parameter)).
Libraries expose a function that validates a percent-decoded `src` value and
derives `srcLog` and `srcWitness` from it, or fails with `invalidDidUrl`:

1. Steps 1–2 of §3.1 apply. The value MUST NOT contain `?` or `#`.
2. `http` and `file` are not allowed.
3. The value MUST continue with `//` and a non-empty authority. This covers
   `https`, and other schemes "with hierarchical paths" such as `ipns`, so
   `urn:` is invalid.
4. **Profile:** one trailing `/` is removed.
5. For `https`: the authority meets §3.1 step 4 (domain name), and the path,
   which may be empty, has segments that are each non-empty and not `.` or `..`.
   They contain no `/`, `\` or NUL once decoded, and don't start or end with a
   Unicode `White_Space` character (U+0009–000D, U+0020, U+0085, U+00A0,
   U+1680, U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000).
6. `srcLog` is `<scheme>:<rest>/did.jsonl` and `srcWitness` is
   `<scheme>:<rest>/did-witness.json`, with the scheme in lowercase and the
   rest as given. No `/.well-known/` path is added.

## 4. DID URLs

A dereferencer turns a did:vh DID URL into a DID, resolution options and a
fragment
([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#reading-didvh-did-urls)).
**Profile:** libraries do it as follows. Every failure is `invalidDidUrl`.

1. The fragment is everything after the first `#`, kept verbatim (possibly
   empty). The query is everything between the first `?` and the fragment.
2. The part before the query MUST be a did:vh DID (§2). **Profile:** a DID URL
   path (`did:vh:<SCID>/…`) is not supported.
3. The query is split on `&`. Each part MUST contain `=`. The name and value
   are each percent-decoded once as UTF-8. `+` is not a space.
4. The resolution-option names `didLog`, `didWitness`, `srcLog`,
   `srcWitness`, `checkWatchers`, `extraWatchers`, `minCopies` and
   `includeDidLog` are not allowed. `src`, `versionId`, `versionTime` and
   `versionNumber` are used, at most once each. Other names are ignored.
5. `src` becomes the `srcLog` and `srcWitness` options (§3.2).
6. `versionNumber` MUST match `[1-9][0-9]{0,15}` and becomes a JSON number.
   `versionId` and `versionTime` stay strings. They are validated by
   `resolve`, which also rejects more than one version selector.

## 5. Resolution

`resolve(did, resolutionOptions)` returns
`{didResolutionMetadata, didDocument, didDocumentMetadata}`
([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#resolution-algorithm)).

**Scope (Profile).** The libraries in this repository are *offline*
resolvers, which the spec permits. They verify a log passed in `didLog`, with
a witness proofs file passed in `didWitness`. They retrieve nothing, and
return `featureNotSupported` where they would have to. A resolver context
flag `remote` says whether the resolver serves other systems. When it does,
a `file` or `loopback` `srcLog` or `srcWitness` is `invalidOptions`.

**Order of checks.**

1. The DID (§2) → `invalidDid`.
2. The options → `invalidOptions`:
   - the options are a JSON object;
   - exactly one of `didLog` and `srcLog`, and at most one of `didWitness`
     and `srcWitness`; `didLog` is a string and `didWitness` an array (its
     records are checked by VH-Log, which gives `invalid-witness-file`);
   - `srcLog` and `srcWitness` are valid references (§3.1), and not
     `file`/`loopback` when `remote`;
   - at most one of `versionId` (a string), `versionTime` (`profile.md` §4
     format) and `versionNumber` (a positive integer);
   - `checkWatchers` is a non-negative integer or `"all"`; `extraWatchers` is
     an array of `https://` URLs, each also meeting the `watchers` URL rule of
     `profile.md` §4; `minCopies` is a positive integer; `includeDidLog` is a
     boolean;
   - **Profile:** other options (for example `accept`) are ignored.
3. `featureNotSupported` for a `srcLog`, a `checkWatchers` other than `0`, or
   a non-empty `extraWatchers`.
4. A `srcWitness` is used only if the log needs witnessing, meaning some
   entry has an active witness list. If it does, this resolver gives
   `featureNotSupported`. Otherwise the `srcWitness` is ignored, as the spec
   requires.
5. VH-Log resolution of `didLog` with the did:vh specialisation for this DID,
   with `versionId`, `versionTime`, `versionNumber` and `minCopies`. With no
   watchers there is one copy, so a `minCopies` above 1 gives
   `insufficientCopies`.
6. If no version was selected and the log has an unsupported entry,
   `featureNotSupported`, because that entry may change the document or its
   keys
   ([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#results-of-processing-the-log)).
   A selected version before the unsupported entry is still returned.

**Errors.** VH-Log errors map to did:vh errors as follows:

| VH-Log | did:vh |
| --- | --- |
| `not-found` | `notFound` |
| `invalid-option` | `invalidOptions` |
| `unsupported-log-version` | `featureNotSupported` |
| `fork-detected` | `logForked` |
| `min-copies-not-met` | `insufficientCopies` |
| anything else (the log, or the requested version, fails verification) | `invalidDid` |

On error, `didResolutionMetadata` is
`{"error": <code>, "problemDetails": {"title": <code>, "detail": <message>, "vhLog"?: <VH-Log error report>}}`,
with `didDocument: null` and `didDocumentMetadata: {}`. `vhLog` is the VH-Log
`{code, version, message}` report (plus `fork` for `logForked`) when the error
came from VH-Log. The harness compares `error` and `vhLog.code`.

**Success.** `didResolutionMetadata` is
`{"contentType": "application/did+json"}`, plus:

- `warnings`: the VH-Log warnings, such as `invalid-entries`, when there are any.
- `didLog` and `didWitness` when `includeDidLog` is `true`
  ([spec](https://github.com/decentralized-identity/didvh/blob/cc2eff6/spec/specification.md#did-resolution-metadata)):
  - `didLog` holds the original lines of the valid entries, each ending in
    `\n`. It is not shortened to the selected version.
  - `didWitness` is included only when the log needs witnessing. **Profile:**
    it is the `didWitness` that was passed (or `[]`), unchanged.

`didDocumentMetadata` has these fields:

| Field | Value |
| --- | --- |
| `versionId`, `versionTime` | of the resolved entry |
| `created` | `versionTime` of entry 1 |
| `updated` | `versionTime` of the last valid entry |
| `scid` | the SCID |
| `deactivated` | the active `deactivated` |
| `ttl` | the active `ttl`, as an integer |
| `witness` | only when witnesses are active: the `witness` parameter, `threshold` an integer |
| `watchers` | **Profile:** always present; `[]` when there are none |

Other VH-Log metadata (`versionNumber`, `updateKeys`, `nextKeyHashes`) is not
returned.

**Deactivation.** When the DID is deactivated, `didDocument` is `null` if the
resolved entry is the last valid entry. That covers both no version selector
and a selector that names the deactivating entry. An earlier version selected
explicitly is returned. `deactivated` is `true` in every case. That the
deactivating entry's own document is not returned when it is selected is a
**Profile** reading of the spec.

## 6. Driver operations

See [`interop-protocol.md`](interop-protocol.md#didvh-operations). A driver
that implements them sets `"didvh": true` in
[`implementations.json`](../implementations.json). The harness then runs the
`didvh` suite against the vectors in [`vectors/didvh`](../vectors/didvh), and
has every did:vh driver resolve the DID logs every other did:vh driver
generated.
