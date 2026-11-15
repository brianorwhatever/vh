#!/usr/bin/env perl
# JSON Lines driver for the interop harness (docs/interop-protocol.md).
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib", "$FindBin::Bin/local/lib/perl5";
use VH::Log ();
use VH::Log::JSON qw(canonicalize decode_utf8 is_object);

binmode STDIN;
binmode STDOUT;
$| = 1;
local $/ = "\n";    # split on LF only, never on CR, U+2028 or U+2029
while (my $line = <STDIN>) {
  chomp $line;
  my $request;
  my $response = eval {
    my $text = decode_utf8($line);
    $request = VH::Log::parse($text);
    die "request must be an object\n" unless is_object($request);
    { id => $request->{id}, ok => JSON::PP::true(), result => VH::Log::dispatch($request->{op}, $request->{input}) };
  };
  my $output = $response && eval { canonicalize($response) };
  unless (defined $output) {
    (my $message = $@ || 'error') =~ s/ at \S+ line \d+\.?\n?\z//;
    chomp $message;
    my $id = is_object($request) ? $request->{id} : undef;
    $output = eval { canonicalize({ id => $id, ok => JSON::PP::false(), error => $message }) }
      // canonicalize({ id => undef, ok => JSON::PP::false(), error => 'unencodable response' });
  }
  utf8::encode($output);
  print $output, "\n";
}
exit 0;
