# VH-Log (Perl)

Perl 5.34+ with one pinned CPAN distribution: [CryptX](https://metacpan.org/dist/CryptX)
0.091 for Ed25519. SHA-256, Unicode normalisation and big-integer constants
come from core modules (Digest::SHA, Unicode::Normalize, Math::BigInt).

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic, the strict JSON parser and the RFC 8785 serialiser are all
Perl; it does not call another implementation.

- `VH::Log` (`lib/VH/Log.pm`) is the library: controller, resolver and proofs.
- `VH::Log::JSON` (`lib/VH/Log/JSON.pm`) parses I-JSON and serialises JCS.
- `driver.pl` is the JSON Lines driver used by the harness.

## Setup

You need Perl 5.34 or newer (the macOS and Ubuntu system perls both work),
`curl`, `make` and a C compiler. Then, in this directory:

```sh
sh build.sh
```

`build.sh` downloads `CryptX-0.091.tar.gz` from CPAN, checks its SHA-256
against the value in the script, and installs it into `./local` (a
local::lib-style tree that `driver.pl` adds to `@INC`). Running it again is a
no-op once that version is installed. The harness runs it automatically.
If you prefer CPAN tooling, `cpanfile` pins the same release:

```sh
cpanm --local-lib local --installdeps .   # or: carton install
```

On Ubuntu the system perl needs no extra packages beyond `build-essential`
and `curl`; nothing is installed outside this directory.

## Library usage

```perl
use lib 'lib', 'local/lib/perl5';
use VH::Log;

my $seed = '11' x 32;
my $created = VH::Log::create({
  state       => { id => 'example:{SCID}' },
  parameters  => { updateKeys => [VH::Log::multikey($seed)] },
  versionTime => '2026-01-01T00:00:00Z',
  signers     => [$seed],
});
my $result = VH::Log::resolve({ log => $created->{log}, now => '2026-06-01T00:00:00Z' });
print $result->{valid} ? "valid\n" : "$result->{error}{code}\n";
```

`create`, `update`, `resolve`, `sign`, `verify`, `witness_proof`, `scid`,
`entry_hash`, `multikey`, `key_hash`, `jcs` and `parse` can be called
directly, and are exportable. Inputs and results have the shapes described in
the [driver protocol](../../docs/interop-protocol.md). Resolution reports
problems with a log in its result and never dies for them.

JSON values use the same conventions as JSON::PP: objects and arrays are hash
and array references, `undef` is `null`, booleans are
`JSON::PP::Boolean` values (`\1` and `\0` are accepted too), and a scalar is a
number if Perl created it as a number. Use `VH::Log::parse` to read JSON
text: it parses every number as a binary64 double, as RFC 8785 requires, so
`123456789012345678` canonicalises to `123456789012345680`. It rejects
non-finite numbers and lone surrogate escapes, and the last of duplicate keys
wins (profile §4).

`VH::Log::verify` and `VH::Log::ed25519_verify` apply the profile's
[Ed25519 acceptance rules](../../docs/profile.md#ed25519-acceptance-profile)
themselves: A and R must be canonical (y < p) and not of small order, and S
must be below L. CryptX's libtomcrypt verifier then decodes the points and
checks the uncofactored equation `[S]B = R + [k]A` with `k` reduced mod L.

## Numbers

RFC 8785 serialises numbers with ECMAScript's shortest round-trip format. Perl
has no such formatter, so `VH::Log::JSON::format_number` searches for it:
`sprintf('%.*e')` is correctly rounded, so the first precision whose output
parses back to the same double gives the shortest digits, and they are the
closest ones. At powers of two, where the rounding interval is asymmetric, the
neighbouring candidate on the other side is tried too. This was checked
against Node on 400,000 doubles (random bit patterns, every power of two, and
decimal-looking values) with no differences.

## did:vh

`VH::Log::DidVh` (`lib/VH/Log/DidVh.pm`) implements did:vh as pinned by
[`docs/didvh-profile.md`](../../docs/didvh-profile.md). The log is verified
by `VH::Log` with the did:vh specialisation (`method` instead of
`logVersion`, a closed parameter set, and a `state.id` check on every entry).

```perl
use VH::Log::DidVh ();
my $did = VH::Log::DidVh::create_did({ document => { id => 'did:vh:{SCID}' },
  parameters => { updateKeys => [VH::Log::multikey($seed)] },
  versionTime => '2026-01-01T00:00:00Z', signers => [$seed] });
my $result = VH::Log::DidVh::resolve_did($did->{did}, { didLog => $did->{log} },
  { now => '2026-06-01T00:00:00Z' });
VH::Log::DidVh::parse_did_url("$did->{did}?versionNumber=1#key-1");
```

The resolver is offline: it verifies the log passed in `didLog` (and
`didWitness`) and returns `featureNotSupported` where it would have to fetch
anything. `check_ref` and `src_references` check `srcLog`/`srcWitness`
references and the `src` DID URL parameter.

## Verification and driver

From this directory:

```sh
prove t
```

From the repository root:

```sh
node harness/run.ts --impl perl --impl typescript
VH_TEST_IMPLS=perl node --test harness/driver-regressions.test.ts
VH_TEST_IMPLS=perl node --test harness/ed25519.test.ts
```

The unit tests cover the JCS vectors and parser edge cases, run the
independent Ed25519 boundary fixtures through the library API, and exercise
creation, rotation, witnessing and partial validity; `t/didvh.t` runs the
did:vh vectors. The harness checks
primitives, resolution, generation, external reference logs and
cross-resolution.

Start the JSON Lines driver with:

```sh
perl driver.pl
```

It reads requests split on LF only, so U+2028, U+2029 and CR inside a line
are never treated as separators. Logs and witness files are supplied by the
caller; the resolver does not fetch network resources.
