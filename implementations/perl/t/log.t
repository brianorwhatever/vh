use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../local/lib/perl5";
use Test::More;
use VH::Log ();
use VH::Log::JSON qw(decode_json true);

my ($seed, $next, $witness) = ('11' x 32, '22' x 32, '33' x 32);
my ($key, $next_key) = map { VH::Log::multikey($_) } $seed, $next;
my $witness_id = 'did:key:' . VH::Log::multikey($witness);
my $now = '2026-06-01T00:00:00Z';

my $created = VH::Log::create({
  state => { id => 'example:{SCID}', count => 1.5 },
  parameters => { updateKeys => [$key], nextKeyHashes => [VH::Log::key_hash($next_key)],
    witness => { threshold => 1, witnesses => [{ id => $witness_id }] } },
  versionTime => '2026-01-01T00:00:00Z',
  signers => [$seed],
});
like $created->{scid}, qr/^Qm/, 'SCID is a SHA-256 multihash';
like $created->{versionId}, qr/^1-Qm/, 'first versionId';
my $entry = decode_json((split /\n/, $created->{log})[0]);
is $entry->{state}{id}, "example:$created->{scid}", '{SCID} replaced';
like $created->{log}, qr/\A\{"versionId":.*"versionTime":.*"parameters":.*"state":.*"proof":/, 'field order';

my $updated = VH::Log::update({
  log => $created->{log}, state => { id => "example:$created->{scid}", count => 2 },
  parameters => { updateKeys => [$next_key], nextKeyHashes => [] },
  versionTime => '2026-02-01T00:00:00Z', signers => [$next],
});
like $updated->{versionId}, qr/^2-Qm/, 'second versionId';

my @file = map { { versionId => $_, proof => [VH::Log::witness_proof($_, $witness)] } } $updated->{versionId};
my $result = VH::Log::resolve({ log => $updated->{log}, witness => \@file, now => $now });
ok $result->{valid}, 'witnessed log resolves';
is $result->{metadata}{versionNumber}, 2, 'latest version';
is $result->{state}{count}, 2, 'latest state';
is_deeply $result->{metadata}{updateKeys}, [$next_key], 'rotated keys';
is $result->{metadata}{deactivated}, VH::Log::JSON::false, 'not deactivated';

my $first = VH::Log::resolve({ log => $updated->{log}, witness => \@file, now => $now, options => { versionNumber => 1 } });
is $first->{state}{count}, 1.5, 'version selection';

my $unwitnessed = VH::Log::resolve({ log => $updated->{log}, now => $now });
ok !$unwitnessed->{valid}, 'missing witness file fails entry 1';
is $unwitnessed->{error}{code}, 'witness-threshold-not-met', 'witness error code';

my $rogue = VH::Log::update({
  log => $updated->{log}, state => { id => 'x' }, versionTime => '2026-03-01T00:00:00Z', signers => [$seed],
});
my $partial = VH::Log::resolve({ log => $rogue->{log}, witness => \@file, now => $now });
ok $partial->{valid}, 'valid prefix still resolves';
is $partial->{firstInvalidVersion}, 3, 'first invalid version';
is $partial->{error}{code}, 'unauthorized-key', 'old key cannot sign after rotation';
is $partial->{metadata}{warnings}[0]{code}, 'invalid-entries', 'partial-validity warning';

(my $tampered = $created->{log}) =~ s/"count":1.5/"count":2.5/;
is VH::Log::resolve({ log => $tampered, now => $now })->{error}{code}, 'invalid-proof', 'tampered state';
is VH::Log::resolve({ log => '', now => $now })->{error}{code}, 'invalid-log', 'empty log';
is VH::Log::resolve({ log => $created->{log}, now => 'yesterday' })->{error}{code}, 'invalid-option', 'bad now';

done_testing;
