# Profile §2 "Ed25519 acceptance", checked through the library API rather
# than the driver, with the repository's independent boundary fixtures.
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../local/lib/perl5";
use Test::More;
use VH::Log ();
use VH::Log::JSON qw(decode_json decode_utf8);

my $cases = decode_json(do {
  open my $fh, '<:raw', "$FindBin::Bin/../../../vectors/ed25519/boundaries.json" or die $!;
  local $/;
  decode_utf8(<$fh>);
});
for my $case (@$cases) {
  my ($input, $expected) = @$case{qw(input expected)};
  if ($case->{op} eq 'verify') {
    is !!VH::Log::verify($input->{document}, $input->{proof}), !!$expected->{valid}, "verify $case->{name}";
  } else {
    my $result = VH::Log::resolve($input);
    is !!$result->{valid}, !!$expected->{valid}, "resolve $case->{name}";
    is $result->{error} && $result->{error}{code}, $expected->{error}, "resolve $case->{name} error"
      if exists $expected->{error};
    is $result->{firstInvalidVersion}, $expected->{firstInvalidVersion}, "resolve $case->{name} firstInvalidVersion"
      if $expected->{firstInvalidVersion};
  }
}

# Raw boundary: the identity point (order 1) as A with R = B and S = 1 is the
# universal forgery the profile rules out; a valid signature still verifies.
my $identity = "\x01" . ("\0" x 31);
my $base = pack 'H*', '5866666666666666666666666666666666666666666666666666666666666666';
ok !VH::Log::ed25519_verify($identity, $base . "\x01" . ("\0" x 31), 'm'), 'identity public key rejected';
my $seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';    # RFC 8032 test 1
my $public = VH::Log::public_key(VH::Log::multikey($seed));
is unpack('H*', $public), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'RFC 8032 public key';
my $proof = VH::Log::sign({ a => 1 }, $seed);
ok VH::Log::verify({ a => 1 }, $proof), 'own signature verifies';
ok !VH::Log::verify({ a => 2 }, $proof), 'other document fails';
my $signature = VH::Log::base58_decode(substr $proof->{proofValue}, 1);
my $high_s = substr($signature, 0, 32) . pack('H*', 'edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
ok !VH::Log::ed25519_verify($public, $high_s, 'x'), 'S = L rejected';
my $non_canonical = pack('H*', 'ed' . ('ff' x 30) . '7f');    # y = p
ok !VH::Log::ed25519_verify($non_canonical, $signature, 'x'), 'non-canonical y rejected';

done_testing;
