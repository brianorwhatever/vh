# did:vh Interop Profile (`didvh-interop-0`)

[did:vh](https://swcurran.github.io/didvh/next/) is a DID method defined as a
*specialisation* of VH-Log: a did:vh DID log **is** a VH-Log log, verified by
the same algorithm, with a few DID-specific rules on top. This profile pins the
choices every did:vh library in this repository makes, so that they can be
tested against each other. It builds on the VH-Log profile,
[`profile.md`](profile.md) (`vh-log-interop-0`), which applies unchanged except
where this document says otherwise.

Pinned spec: [`swcurran/didvh-old@6c2e753`](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md)
(the `swcurran/didvh` repository currently holds only a Spec-Up template; see
[`spec.lock.json`](../spec.lock.json)). The did:vh spec is a **pre-draft** and
asks not to be implemented against until it reaches Draft. These libraries
exist to test the spec, and will follow it as it changes. Spec issues found
while writing this profile are in [`spec-notes.md`](spec-notes.md#didvh).

Where a rule restates the spec, the spec is linked; **Profile** marks our own
choices.

## 1. Specialisation hook

Each VH-Log library takes a *specialisation* when it verifies a log. Plain
VH-Log is one; did:vh is another. A specialisation sets:

| | VH-Log | did:vh |
| --- | --- | --- |
| Version parameter | `logVersion` | `method` |
| Accepted values | `vh-log:1.0` | `did:vh:1.0` |
| Unknown parameters | ignored | **rejected** (`invalid-parameter`): the set is closed |
| State check | none | `state.id` (§2) |

Everything else (encodings, SCID, entry hash, proofs, Ed25519 acceptance,
witnesses, pre-rotation, version selection, partial validity) is VH-Log as
pinned by `profile.md`. Because the version parameter differs, a plain VH-Log
log is not a valid did:vh log, and the reverse is also true.

**Check order.** The did:vh rules slot into `profile.md` §4 as follows:

- In check 3 (parameters), the closed-set check runs first, right after the
  null check. So a did:vh entry with `logVersion` or `portable` fails with
  `invalid-parameter`. A first entry without `method` fails with
  `unsupported-log-version`, as does a `method` that is not `did:vh:1.0`
  (for example `did:webvh:1.0`). `method` may appear again in later entries
  under the same rules as `logVersion`.
- A new **check 8**, after the SCID check, runs on every entry: the state
  check (§2). It fails with the new VH-Log error code `invalid-state`.

The did:vh parameter set is `method`, `scid`, `updateKeys`, `nextKeyHashes`,
`witness`, `watchers`, `deactivated` and `ttl`
([spec](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md#didvh-did-method-parameters)).
Witness ids are `did:key` DIDs, which `profile.md` §3 already requires.

## 2. The DID and the DID document

- A did:vh DID is `did:vh:` followed by exactly 46 base58btc characters
  ([ABNF](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md#method-specific-identifier)).
  The method name is lowercase only. Anything else is `invalidDid`.
- **State check (check 8).** Every entry's `state.id` MUST be exactly
  `did:vh:<SCID>`, where `<SCID>` is the log's `scid` parameter. When
  resolving a DID, the log's SCID MUST also equal the DID's. A mismatch of
  either kind fails that entry with `invalid-state`. So a valid log for a
  different DID fails at entry 1, and a later entry that changes `state.id`
  invalidates that entry and everything after it, under the usual partial
  validity rules.
- **Profile:** nothing else in the DID document is validated. It is a JSON
  object with the right `id`.
- **Create.** The genesis DID document uses `did:vh:{SCID}` wherever it refers
  to the DID. Generators add `"method": "did:vh:1.0"` and
  `"scid": "{SCID}"` to the parameters if they are absent, after the caller's
  own parameters (`method` first, then `scid`), and do not validate their
  input, as in `profile.md` §5.

## 3. `src` references

The `src` resolution option and DID URL parameter name the location of
`did.jsonl` and `did-witness.json`
([spec](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md#the-src-option)).
Libraries expose a function that validates a `src` value and returns its kind
and the URLs of both files. The rules below are how this profile reads the
spec, made exact.

1. **Profile:** the value MUST be a string of printable ASCII
   (U+0021–U+007E). In particular, an internationalised host MUST already be
   in its A-label (punycode) form. The spec instead requires the resolver to
   convert it, which would need an IDNA2008 library in every language (see
   `spec-notes.md`).
2. It MUST start with a scheme, `[A-Za-z][A-Za-z0-9+.-]*:`, which is compared
   case-insensitively and written in lowercase in the output.
3. It MUST NOT contain `?` or `#` (no query or fragment), whatever the scheme.
4. **`https` and `http` (web location / loopback).**
   - After the scheme comes `//` and an authority, which runs up to the next
     `/` or the end. The path is the rest. **Profile:** one trailing `/` is
     removed from the path.
   - **Profile:** the authority MUST NOT contain `@` (no user information).
   - Host and port: an authority starting with `[` is an IP literal running to
     `]`; otherwise the host runs to the first `:`. If there is a port, it is
     1–5 digits with value ≤ 65535. The host is compared in lowercase.
   - `https`: the host MUST be a domain name: optionally one trailing `.`,
     then 1–253 characters of dot-separated labels, each 1–63 characters of
     `a-z`, `0-9` and `-`, not starting or ending with `-`. The last label
     MUST NOT be all digits, which rules out IPv4 literals. IP literals in
     `[...]` are not domain names. Kind `web`.
   - `http`: the host MUST be a loopback host: `localhost`, `[::1]`, or an
     IPv4 dotted quad with first octet 127 (each octet decimal 0–255, with no
     leading zeros). Kind `loopback`.
   - Each path segment is percent-decoded as UTF-8. A malformed escape or
     invalid UTF-8 makes the value invalid. The decoded segment MUST be
     non-empty, MUST NOT be `.` or `..`, MUST NOT contain `/`, `\` or NUL, and
     MUST NOT start or end with a Unicode `White_Space` character (U+0009–000D,
     U+0020, U+0085, U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F,
     U+205F, U+3000).
   - Files: with an empty path, `<scheme>://<authority>/.well-known/did.jsonl`
     and `/.well-known/did-witness.json`. Otherwise `<scheme>://<authority><path>/did.jsonl`
     and `/did-witness.json`. The authority and path are written as given, not
     decoded or case-folded.
5. **`file` (local directory).** Accepted forms are `file:///<path>`,
   `file://localhost/<path>` (host compared case-insensitively) and
   `file:/<path>`. Any other host is invalid, and so is a path that does not
   start with `/`. One trailing `/` is removed, and the files are
   `file://<path>/did.jsonl` and `file://<path>/did-witness.json`, with the
   host dropped. Kind `file`.
6. **Any other scheme.** The value MUST continue with `//` and a non-empty
   authority (it must be hierarchical). Otherwise it is invalid, which covers
   `urn:` and `did:`. One trailing `/` is removed, and `/did.jsonl` and
   `/did-witness.json` are appended. Kind `other`.

An invalid value is `invalidOptions` as a resolution option, and
`invalidDidUrl` in a DID URL.

## 4. DID URLs

A dereferencer turns a did:vh DID URL into a DID, resolution options and a
fragment
([spec](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md#reading-didvh-did-urls)).
**Profile:** libraries do it as follows. Every failure is `invalidDidUrl`.

1. The fragment is everything after the first `#`, kept verbatim (possibly
   empty). The query is everything between the first `?` and the fragment.
2. The part before the query MUST be a did:vh DID (§2). **Profile:** a DID URL
   path (`did:vh:<SCID>/…`) is not supported.
3. The query is split on `&`. Each part MUST contain `=`. The name and value
   are each percent-decoded once as UTF-8. `+` is not a space.
4. `didLog` and `didWitness` are not allowed. Of the other names, only `src`,
   `versionId`, `versionTime` and `versionNumber` are used. Any other name is
   ignored. Each used name may appear at most once.
5. `src` MUST be a valid reference (§3) and MUST NOT be of kind `file` or
   `loopback`.
6. `versionNumber` MUST match `[1-9][0-9]{0,15}` and becomes a JSON number.
   `versionId` and `versionTime` stay strings. They are validated by
   `resolve`, which also rejects more than one version selector.

## 5. Resolution

`resolve(did, resolutionOptions)` returns
`{didResolutionMetadata, didDocument, didDocumentMetadata}`
([spec](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md#resolution-algorithm)).

**Scope (Profile).** The libraries in this repository are *offline*
resolvers. They verify a log passed directly in `didLog` (and `didWitness`).
They do not retrieve anything. A valid `src`, `checkWatchers: true` or a
non-empty `extraWatchers` gives `featureNotSupported`, which the spec permits.
A resolver context flag `remote` says whether the resolver serves other
systems. When it does, a `file` or `loopback` `src` is `invalidOptions`
instead.

**Order of checks.**

1. The DID (§2) → `invalidDid`.
2. The options → `invalidOptions`:
   - the options are a JSON object;
   - exactly one of `didLog` and `src`; `didLog` is a string;
   - `didWitness` only with `didLog`, and it is an array (its records are
     checked by VH-Log, which gives `invalid-witness-file`);
   - at most one of `versionId` (a string), `versionTime` (`profile.md` §4
     format) and `versionNumber` (a positive integer);
   - `minCopies` is a positive integer, `checkWatchers` a boolean, and
     `extraWatchers` an array of `https://` URLs, each also meeting the
     `watchers` URL rule of `profile.md` §4;
   - `src` is a valid reference (§3), and not `file`/`loopback` when `remote`.
   - **Profile:** other options (for example `accept`) are ignored.
3. `src`, `checkWatchers: true`, or non-empty `extraWatchers` →
   `featureNotSupported`.
4. VH-Log resolution of `didLog` with the did:vh specialisation for this DID,
   with the options `versionId`, `versionTime`, `versionNumber` and
   `minCopies`. With no watchers there is one copy, so `minCopies` above 1
   gives `insufficientCopies`.

**Errors.** VH-Log errors map to did:vh errors as follows:

| VH-Log | did:vh |
| --- | --- |
| `not-found` | `notFound` |
| `invalid-option` | `invalidOptions` |
| `fork-detected` | `logForked` |
| `min-copies-not-met` | `insufficientCopies` |
| anything else (the log, or the requested version, fails verification) | `invalidDid` |

On error, `didResolutionMetadata` is
`{"error": <code>, "problemDetails": {"title": <code>, "detail": <message>, "vhLog"?: <VH-Log error report>}}`,
with `didDocument: null` and `didDocumentMetadata: {}`. `vhLog` is the VH-Log
`{code, version, message}` report (plus `fork` for `logForked`) when the error
came from VH-Log. The harness compares `error` and `vhLog.code`.

**Success.** `didResolutionMetadata` is
`{"contentType": "application/did+json"}`, plus `warnings` (the VH-Log
warnings, such as `invalid-entries`) when there are any. `didDocumentMetadata`
is built from the VH-Log result
([spec](https://github.com/swcurran/didvh-old/blob/6c2e753/spec/specification.md#did-resolution-metadata)):

| Field | Value |
| --- | --- |
| `versionId`, `versionTime` | of the resolved entry |
| `created` | `versionTime` of entry 1 |
| `updated` | `versionTime` of the last valid entry |
| `scid` | the SCID |
| `deactivated` | the active `deactivated` |
| `ttl` | the active `ttl`, as a decimal **string** |
| `witness` | only when witnesses are active: `{"threshold": "<string>", "witnesses": [...]}` |
| `watchers` | **Profile:** always present; `[]` when there are none |

Other VH-Log metadata (`versionNumber`, `updateKeys`, `nextKeyHashes`) is not
returned.

**Deactivation.** When the DID is deactivated and the resolved entry is the
last valid entry (no version selector, or a selector that names the
deactivating entry), `didDocument` is `null`. An earlier version selected
explicitly is returned, and `deactivated` is `true` in every case. That the
deactivating entry's own document is not returned when selected is a
**Profile** reading of "Prior versions MAY be resolved".

## 6. Driver operations

See [`interop-protocol.md`](interop-protocol.md#didvh-operations). A driver
that implements them sets `"didvh": true` in
[`implementations.json`](../implementations.json). The harness then runs the
`didvh` suite against the vectors in [`vectors/didvh`](../vectors/didvh), and
has every did:vh driver resolve the DID logs every other did:vh driver
generated.
