use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../local/lib/perl5";
use Test::More;
use VH::Log ();
use VH::Log::DidVh ();
use VH::Log::JSON qw(decode_json decode_utf8 canonicalize is_number);

# did:vh: the library must reproduce every did:vh vector, and the
# specialisation hook must keep VH-Log and did:vh logs apart.
my $vectors = "$FindBin::Bin/../../../vectors/didvh";
sub load {
  open my $fh, '<:raw', "$vectors/$_[0]" or die "$_[0]: $!";
  local $/;
  return decode_json(decode_utf8(<$fh>));
}
sub same { canonicalize($_[0] // undef) eq canonicalize($_[1] // undef) }

opendir my $dir, "$vectors/resolution" or die $!;
for my $file (sort grep { /\.json\z/ } readdir $dir) {
  for my $c (@{ load("resolution/$file")->{cases} }) {
    my ($i, $x) = @$c{qw(input expect)};
    my $r = VH::Log::DidVh::resolve_did($i->{did}, $i->{options}, { now => $i->{now}, remote => $i->{remote} });
    my $meta = $r->{didResolutionMetadata};
    my $name = "resolution/$file/$c->{name}";
    if ($x->{error}) {
      is $meta->{error}, $x->{error}, "$name: error";
      is $meta->{problemDetails}{vhLog} && $meta->{problemDetails}{vhLog}{code}, $x->{vhLogError}, "$name: vhLog";
    } else {
      ok !$meta->{error}, "$name: no error";
      ok same($r->{didDocument}, $x->{didDocument}), "$name: didDocument";
      ok same($r->{didDocumentMetadata}, $x->{didDocumentMetadata}), "$name: didDocumentMetadata";
      is_deeply [sort map { $_->{code} } @{ $meta->{warnings} // [] }], $x->{warnings} // [], "$name: warnings";
      ok same($meta->{didLog}, $x->{didLog}), "$name: didLog";
      ok same($meta->{didWitness}, $x->{didWitness}), "$name: didWitness";
    }
  }
}

for (['ref.json', 'didvh-ref', 'ref'], ['src.json', 'didvh-src', 'src'], ['did-url.json', 'didvh-did-url', 'didUrl']) {
  my ($file, $op, $field) = @$_;
  for my $c (@{ load($file)->{cases} }) {
    my $got = VH::Log::dispatch($op, { $field => $c->{$field} });
    ok same($got, $c->{expect}), "$file/$c->{name}";
    ok is_number($got->{options}{versionNumber}), "$file/$c->{name}: versionNumber is a number"
      if $got->{options} && exists $got->{options}{versionNumber};
  }
}

my $seed = '11' x 32;
my $key = VH::Log::multikey($seed);
my $now = '2026-06-01T00:00:00Z';
my $created = VH::Log::DidVh::create_did({ document => { id => 'did:vh:{SCID}', controller => 'did:vh:{SCID}' },
  parameters => { updateKeys => [$key] }, versionTime => '2026-01-01T00:00:00Z', signers => [$seed] });
is VH::Log::DidVh::parse_did($created->{did}), $created->{scid}, 'DID carries the SCID';
my $line = decode_json((split /\n/, $created->{log})[0]);
is $line->{parameters}{method}, 'did:vh:1.0', 'method added';
ok !exists $line->{parameters}{logVersion}, 'no logVersion';
is $line->{state}{controller}, $created->{did}, '{SCID} replaced';

my $updated = VH::Log::DidVh::update_did({ log => $created->{log}, document => { id => $created->{did}, v => 2 },
  versionTime => '2026-01-02T00:00:00Z', signers => [$seed] });
my $r = VH::Log::DidVh::resolve_did($created->{did}, { didLog => $updated->{log} }, { now => $now });
is $r->{didDocument}{v}, 2, 'latest document';
is $r->{didDocumentMetadata}{versionId}, $updated->{versionId}, 'latest versionId';

my $vh = VH::Log::create({ state => { id => 'did:vh:{SCID}' }, parameters => { updateKeys => [$key] },
  versionTime => '2026-01-01T00:00:00Z', signers => [$seed] });
is VH::Log::DidVh::resolve_did("did:vh:$vh->{scid}", { didLog => $vh->{log} }, { now => $now })
  ->{didResolutionMetadata}{error}, 'invalidDid', 'a VH-Log log is not a did:vh log';
is VH::Log::resolve({ log => $created->{log}, now => $now })->{error}{code}, 'unsupported-log-version',
  'a did:vh log is not a VH-Log log';

done_testing;
