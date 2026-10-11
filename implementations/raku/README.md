# VH-Log for Raku

Independent Rakudo library for `vh-log-interop-0`, based on VH-Log specification
commit `f2f9fda`. All log processing, parsing, canonicalization, encodings and
resolution are implemented in Raku. NativeCall uses libsodium for SHA-256,
SHA-512 and Ed25519. A small C++17 helper supplies standard shortest binary64
digits; Raku applies RFC 8785 / ECMAScript number layout.

## Setup

On macOS:

```sh
brew install rakudo libsodium
cd implementations/raku
sh scripts/build.sh
sh scripts/test.sh
```

Verified locally with Rakudo 2026.09, Homebrew libsodium 1.0.22 and Apple Clang.
On Linux, install Perl, Git, curl, make, and a C++17 compiler, then use
`scripts/setup-linux.sh`. This builds checksum-pinned Rakudo 2026.09 and libsodium
1.0.20 under `.deps`, without global installation. Compiler/system packages
are supplied by the host. Set `VHLOG_SODIUM` to override the shared-library path.

`sh scripts/run.sh` runs the JSON Lines driver. It accepts every operation in
[the interop protocol](../../docs/interop-protocol.md). Standard output contains
only response JSON; errors belong to response envelopes or standard error.

From the repository root:

```sh
node harness/run.ts --impl raku
node harness/run.ts --impl typescript --impl raku --suite cross
```

## Library API

Run Raku from this directory with `-Ilib`, or add its absolute `lib` path when
using the library from another working directory.

```raku
use VHLog;
use VHLog::Crypto;
use VHLog::JSON;

my $seed = '00' x 32;
my $key = multikey($seed);
my $initial = create-log({
    state => { id => 'example:{SCID}', message => 'hello' },
    parameters => { updateKeys => [$key] },
    versionTime => '2026-01-01T00:00:00Z',
    signers => [$seed],
});
my $updated = update-log({
    log => $initial<log>, state => { message => 'updated' }, parameters => {},
    versionTime => '2026-01-01T00:00:01Z', signers => [$seed],
});
my $result = resolve-log({
    log => $updated<log>, now => '2026-01-02T00:00:00Z',
    options => { versionNumber => 1 },
});
say $result<state><message>; # hello
```

Exported operations:

| Module | Functions |
| --- | --- |
| `VHLog` | `create-log`, `update-log`, `resolve-log`, `entry-hash`, `scid`, `dispatch` |
| `VHLog::JSON` | `parse-json`, `jcs`, `quote-json`, `cps` |
| `VHLog::Crypto` | `sha` (256 or 512), `b58`, `un58`, `hash-text`, `valid-hash`, `public-key`, `multikey`, `method-key`, `without-proof`, `sign`, `verify` |

`sign($document, $seed, :$verificationMethod, :$created)` creates a proof;
`verify($document, $proof)` verifies it without checking authorization. Witness
proofs sign `{ versionId => $version-id }`. `resolve-log` accepts the same hash
as the protocol's resolve input and returns the protocol result. Copies are
supplied as data; the library performs no network requests.

Raku flattens a single hash in a list literal unless it is itemized. Use a
trailing comma for arrays containing one object, for example
`copies => [{ source => 'watcher', log => $updated<log> },]`.

Raku's ordinary strings use Unicode normalization. For byte-faithful JSON,
read bytes and decode with `utf8-c8`, then call `parse-json`; encode `jcs` output
with `utf8-c8`. The parser preserves original Unicode code points, treats every
number as binary64, rejects non-finite numbers and invalid Unicode, and retains
the last duplicate key. Constructing ordinary Raku strings can normalize them
before the library receives them.
