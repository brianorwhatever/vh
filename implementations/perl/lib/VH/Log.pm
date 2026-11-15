package VH::Log;
# VH-Log, interop profile vh-log-interop-0 (docs/profile.md). All protocol
# logic is Perl; CryptX supplies Ed25519 and Digest::SHA supplies SHA-256.
use strict;
use warnings;
use Carp qw(croak);
use Crypt::PK::Ed25519 ();
use Digest::SHA ();
use Math::BigInt ();
use POSIX ();
use Scalar::Util qw(blessed);
use Unicode::Normalize ();
use VH::Log::JSON qw(decode_json canonicalize is_number is_string is_bool is_object is_array true false);
use Exporter 'import';

our $VERSION = '0.1.0';
our @EXPORT_OK = qw(parse jcs hash_b58 multikey key_hash scid entry_hash sign verify
  witness_proof create update resolve dispatch);

my $ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
my %DIGIT = map { substr($ALPHABET, $_, 1) => $_ } 0 .. 57;
my $MULTIHASH = "\x12\x20";
my $ED25519_CODEC = "\xed\x01";

# Errors in a log are reported as values; this class carries them out of
# nested checks. Other exceptions mean the caller misused the API.
package VH::Log::Error {
  sub new {
    my ($class, $code, $version, $fork) = @_;
    my %report = (code => $code, version => $version, message => $code);
    $report{fork} = $fork if $fork;
    return bless { report => \%report }, $class;
  }
  sub report { $_[0]{report} }
}

sub _fail { die VH::Log::Error->new(@_) }

# ------------------------------------------------------------- encodings

sub parse { decode_json(@_) }

sub jcs { canonicalize(@_) }

sub _utf8 { my $s = shift; utf8::encode($s); $s }

sub _sha256 { Digest::SHA::sha256(_utf8(shift)) }

sub base58_encode {
  my @bytes = unpack 'C*', shift;
  my $zeros = 0;
  $zeros++ while $zeros < @bytes && !$bytes[$zeros];
  my @digits;
  for my $byte (@bytes) {
    my $carry = $byte;
    for my $d (@digits) {
      $carry += $d << 8;
      $d = $carry % 58;
      $carry = int($carry / 58);
    }
    while ($carry) { push @digits, $carry % 58; $carry = int($carry / 58) }
  }
  return ('1' x $zeros) . join '', map { substr $ALPHABET, $_, 1 } reverse @digits;
}

# Returns the bytes, or undef if the text is not base58btc.
sub base58_decode {
  my $s = shift;
  return undef unless is_string($s);
  my ($ones) = $s =~ /^(1*)/;
  my @bytes;
  for my $c (split //, $s) {
    my $carry = $DIGIT{$c};
    return undef unless defined $carry;
    for my $b (@bytes) {
      $carry += $b * 58;
      $b = $carry & 0xff;
      $carry >>= 8;
    }
    while ($carry) { push @bytes, $carry & 0xff; $carry >>= 8 }
  }
  pop @bytes while @bytes && !$bytes[-1];
  return ("\0" x length $ones) . pack 'C*', reverse @bytes;
}

sub hash_b58 { base58_encode($MULTIHASH . _sha256(shift)) }

sub key_hash { hash_b58(shift) }

sub _check_hash {
  my $bytes = base58_decode(shift);
  return 'not-base58' unless defined $bytes;
  return length($bytes) == 34 && substr($bytes, 0, 2) eq $MULTIHASH ? 'ok' : 'unsupported-algorithm';
}

# The 32-byte Ed25519 public key in a multikey, or undef.
sub public_key {
  my $mk = shift;
  return undef unless is_string($mk) && $mk =~ /^z/;
  my $bytes = base58_decode(substr $mk, 1);
  return undef unless defined $bytes && length $bytes == 34 && substr($bytes, 0, 2) eq $ED25519_CODEC;
  return substr $bytes, 2;
}

my %SIGNERS;
sub _signer {
  my $seed = shift;
  croak 'seed must be 32 bytes of hex' unless is_string($seed) && $seed =~ /\A[0-9a-fA-F]{64}\z/;
  return $SIGNERS{lc $seed} //= Crypt::PK::Ed25519->new->import_key_raw(pack('H*', $seed), 'private');
}

sub multikey {
  my $seed = shift;
  return 'z' . base58_encode($ED25519_CODEC . _signer($seed)->export_key_raw('public'));
}

sub _method_key {
  my $vm = shift;
  return undef unless is_string($vm) && $vm =~ /\Adid:key:([^#]+)#(.+)\z/;
  return $1 eq $2 && defined public_key($1) ? $1 : undef;
}

sub _signing_input {
  my ($document, $config) = @_;
  return _sha256(jcs($config)) . _sha256(jcs($document));
}

sub _without {
  my ($hash, $key) = @_;
  my %copy = %$hash;
  delete $copy{$key};
  return \%copy;
}

# eddsa-jcs-2022 proof over $document. $options may set verificationMethod
# and created.
sub sign {
  my ($document, $seed, $options) = @_;
  $options //= {};
  my $mk = multikey($seed);
  my %config = (type => 'DataIntegrityProof', cryptosuite => 'eddsa-jcs-2022',
    verificationMethod => exists $options->{verificationMethod} ? $options->{verificationMethod} : "did:key:$mk#$mk",
    proofPurpose => 'assertionMethod');
  $config{created} = $options->{created} if exists $options->{created};
  my $signature = _signer($seed)->sign_message(_signing_input($document, \%config));
  return { %config, proofValue => 'z' . base58_encode($signature) };
}

sub witness_proof {
  my ($version_id, $seed, $options) = @_;
  return sign({ versionId => $version_id }, $seed, $options);
}

# ----------------------------------------------------- Ed25519 acceptance

# Big-endian 64-digit hex, so that string comparison is numeric comparison.
sub _hex32 { my $hex = substr Math::BigInt->new(shift)->as_hex, 2; ('0' x (64 - length $hex)) . lc $hex }
my $P = _hex32('57896044618658097711785492504343953926634992332820282019728792003956564819949');
my $L = _hex32('7237005577332262213973186563042994240857116359379907606001950938285454250989');
# y-coordinates of the eight points of order dividing 8; with y < p these
# cover every encoding of them, including both sign bits.
my %SMALL_ORDER_Y = map { _hex32($_) => 1 } qw(0 1
  2707385501144840649318225287225658788936804267575313519463743609750303402022
  55188659117513257062467267217118295137698188065244968500265048394206261417927
  57896044618658097711785492504343953926634992332820282019728792003956564819948);

sub _le_hex { my @b = unpack 'C32', shift; $b[31] &= 0x7f if $_[0]; unpack 'H*', pack 'C*', reverse @b }

# Profile §2 "Ed25519 acceptance". Encoded A and R must be canonical (y < p)
# and must not have order dividing 8; S must be below L. CryptX (libtomcrypt)
# then decodes the points onto the curve, re-checks S, and checks the
# uncofactored equation [S]B = R + [k]A with k reduced modulo L by comparing
# the canonical encoding of [S]B - [k]A with R.
sub ed25519_verify {
  my ($public, $signature, $message) = @_;
  return 0 unless defined $public && defined $signature && length $public == 32 && length $signature == 64;
  for my $point ($public, substr($signature, 0, 32)) {
    my $y = _le_hex($point, 1);
    return 0 unless $y lt $P && !$SMALL_ORDER_Y{$y};
  }
  return 0 unless _le_hex(substr($signature, 32), 0) lt $L;
  my $ok = eval {
    Crypt::PK::Ed25519->new->import_key_raw($public, 'public')->verify_message($signature, $message);
  };
  return $ok ? 1 : 0;
}

# Checks an eddsa-jcs-2022 signature only (no authorisation).
sub verify {
  my ($document, $proof) = @_;
  return 0 unless is_object($proof) && is_object($document);
  for (['type', 'DataIntegrityProof'], ['cryptosuite', 'eddsa-jcs-2022'], ['proofPurpose', 'assertionMethod']) {
    my $v = $proof->{ $_->[0] };
    return 0 unless is_string($v) && $v eq $_->[1];
  }
  my $mk = _method_key($proof->{verificationMethod});
  my $value = $proof->{proofValue};
  return 0 unless defined $mk && is_string($value) && $value =~ /^z/;
  my $signature = base58_decode(substr $value, 1);
  return 0 unless defined $signature && length $signature == 64;
  my $input = eval { _signing_input($document, _without($proof, 'proofValue')) };
  return 0 unless defined $input;
  return ed25519_verify(public_key($mk), $signature, $input);
}

# ---------------------------------------------------------- log entries

sub scid { hash_b58(jcs(_without(shift, 'proof'))) }

sub entry_hash {
  my ($entry, $previous) = @_;
  return hash_b58(jcs({ %{ _without($entry, 'proof') }, versionId => $previous }));
}

sub _lines {
  my $log = shift;
  croak 'log must be a string' unless is_string($log);
  my @lines = split /\n/, $log, -1;
  pop @lines if @lines && $lines[-1] eq '';
  return \@lines;
}

# A log line with the profile's field order.
sub _serialize_entry {
  my $e = shift;
  my @order = grep { exists $e->{$_} } qw(versionId versionTime parameters state proof);
  my %known = map { $_ => 1 } @order;
  my @rest = sort grep { !$known{$_} } keys %$e;
  return '{' . join(',', map { jcs("$_") . ':' . jcs($e->{$_}) } @order, @rest) . '}';
}

sub _signers {
  my $signers = shift;
  croak 'signers must be an array' unless is_array($signers);
  return @$signers;
}

sub create {
  my $input = shift;
  croak 'parameters must be an object' unless is_object($input->{parameters});
  my %parameters = (logVersion => 'vh-log:1.0', scid => '{SCID}', %{ $input->{parameters} });
  my $entry = { versionId => '{SCID}', versionTime => $input->{versionTime},
    parameters => \%parameters, state => $input->{state} };
  my $id = scid($entry);
  my $text = jcs($entry);
  $text =~ s/\{SCID\}/$id/g;
  $entry = parse($text);
  $entry->{versionId} = '1-' . entry_hash($entry, $id);
  $entry->{proof} = [map { sign($entry, $_, { created => $input->{versionTime} }) } _signers($input->{signers})];
  return { log => _serialize_entry($entry) . "\n", scid => $id, versionId => $entry->{versionId} };
}

sub update {
  my $input = shift;
  my $log = $input->{log};
  my $lines = _lines($log);
  croak 'log is empty' unless @$lines;
  my $previous = parse($lines->[-1])->{versionId};
  croak 'last entry has no versionId' unless is_string($previous);
  my $entry = { versionId => $previous, versionTime => $input->{versionTime},
    parameters => exists $input->{parameters} ? $input->{parameters} : {}, state => $input->{state} };
  my ($number) = $previous =~ /^([0-9]+)/;
  $entry->{versionId} = (($number // 0) + 1) . '-' . entry_hash($entry, $previous);
  $entry->{proof} = [map { sign($entry, $_, { created => $input->{versionTime} }) } _signers($input->{signers})];
  my $prefix = $log . ($log =~ /\n\z/ ? '' : "\n");
  return { log => $prefix . _serialize_entry($entry) . "\n", versionId => $entry->{versionId} };
}

# ------------------------------------------------------------ resolution

# Seconds since 1970 for a profile versionTime, or undef.
sub _time {
  my $value = shift;
  return undef unless is_string($value)
    && $value =~ /\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\+00:00)\z/;
  my ($y, $m, $d, $h, $mi, $s) = ($1 + 0, $2 + 0, $3 + 0, $4 + 0, $5 + 0, $6 + 0);
  return undef unless $m >= 1 && $m <= 12 && $h < 24 && $mi < 60 && $s < 60;
  my $leap = ($y % 4 == 0 && $y % 100 != 0) || $y % 400 == 0;
  my $days_in_month = (31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[$m - 1];
  return undef unless $d >= 1 && $d <= $days_in_month;
  # Days from civil (proleptic Gregorian).
  my $yy = $m <= 2 ? $y - 1 : $y;
  my $era = POSIX::floor($yy / 400);
  my $yoe = $yy - $era * 400;
  my $doy = int((153 * ($m > 2 ? $m - 3 : $m + 9) + 2) / 5) + $d - 1;
  my $doe = $yoe * 365 + int($yoe / 4) - int($yoe / 100) + $doy;
  my $days = $era * 146097 + $doe - 719468;
  return $days * 86400 + $h * 3600 + $mi * 60 + $s;
}

sub _integer { my $v = shift; is_number($v) && $v == $v && $v - $v == 0 && $v == int($v) }

sub _strings { my $v = shift; is_array($v) && !grep { !is_string($_) } @$v }

sub _str_eq { my ($v, $s) = @_; is_string($v) && $v eq $s }

my @KNOWN = qw(logVersion scid updateKeys nextKeyHashes witness watchers ttl);

sub _parameters {
  my ($raw, $previous, $n) = @_;
  _fail('invalid-parameter', $n) if grep { !defined } values %$raw;
  _fail('unsupported-log-version', $n)
    if (!$previous && !exists $raw->{logVersion}) || (exists $raw->{logVersion} && !_str_eq($raw->{logVersion}, 'vh-log:1.0'));
  _fail('invalid-parameter', $n)
    if $previous ? exists $raw->{scid} : (!is_string($raw->{scid}) || !exists $raw->{updateKeys});
  if (exists $raw->{updateKeys}) {
    _fail('invalid-parameter', $n)
      unless _strings($raw->{updateKeys}) && !grep { !defined public_key($_) } @{ $raw->{updateKeys} };
  }
  if (exists $raw->{nextKeyHashes}) {
    _fail('invalid-parameter', $n)
      unless _strings($raw->{nextKeyHashes}) && !grep { _check_hash($_) ne 'ok' } @{ $raw->{nextKeyHashes} };
  }
  my %p = $previous ? %$previous : (nextKeyHashes => [], witness => undef, watchers => [], ttl => 3600);
  $p{$_} = $raw->{$_} for grep { exists $raw->{$_} } @KNOWN;
  $p{deactivated} = exists $raw->{deactivated} ? $raw->{deactivated} : false;
  if (exists $raw->{witness}) {
    my $w = $raw->{witness};
    _fail('invalid-parameter', $n) unless is_object($w);
    if (!%$w) {
      $p{witness} = undef;
    } else {
      my $ws = $w->{witnesses};
      _fail('invalid-parameter', $n) unless is_array($ws) && @$ws && !grep {
        !(is_object($_) && is_string($_->{id}) && $_->{id} =~ /^did:key:/ && defined public_key(substr $_->{id}, 8))
      } @$ws;
      my %seen;
      my @ids = grep { !$seen{$_}++ } map { Unicode::Normalize::NFC($_->{id}) } @$ws;
      my $t = $w->{threshold};
      _fail('invalid-parameter', $n) unless @ids == @$ws && _integer($t) && $t >= 1 && $t <= @ids;
      $p{witness} = { threshold => $t, witnesses => $ws };
    }
  }
  if (exists $raw->{watchers}) {
    _fail('invalid-parameter', $n) unless _strings($raw->{watchers})
      && !grep { !(/\A[\x21-\x7e]+\z/ && m{\Ahttps?://[^/?#]}) } @{ $raw->{watchers} };
  }
  _fail('invalid-parameter', $n) unless is_bool($p{deactivated});
  _fail('invalid-parameter', $n) unless _integer($p{ttl}) && $p{ttl} >= 0 && $p{ttl} <= 2**31;
  if ($previous && @{ $previous->{nextKeyHashes} }) {
    _fail('prerotation-violation', $n) unless exists $raw->{updateKeys} && exists $raw->{nextKeyHashes};
    my %committed = map { $_ => 1 } @{ $previous->{nextKeyHashes} };
    $committed{ hash_b58($_) } or _fail('prerotation-violation', $n) for @{ $raw->{updateKeys} };
  }
  return \%p;
}

sub _verify_entry {
  my ($e, $previous, $now) = @_;
  my $n = $previous ? $previous->{n} + 1 : 1;
  _fail('entry-after-deactivation', $n) if $previous && $previous->{p}{deactivated};
  _fail('invalid-entry', $n) unless join(',', sort keys %$e) eq 'parameters,proof,state,versionId,versionTime'
    && is_string($e->{versionId}) && is_string($e->{versionTime}) && is_object($e->{parameters})
    && is_object($e->{state}) && is_array($e->{proof});
  my $pp = $previous && $previous->{p};
  my $p = _parameters($e->{parameters}, $pp, $n);
  my $keys = !$pp || @{ $pp->{nextKeyHashes} } ? $p->{updateKeys} : $pp->{updateKeys};
  my $rule = !$pp || (exists $e->{parameters}{witness} && !$pp->{witness}) ? $p->{witness} : $pp->{witness};
  _fail('invalid-proof', $n) unless @{ $e->{proof} };
  my %authorised = map { $_ => 1 } @$keys;
  my $document = _without($e, 'proof');
  for my $proof (@{ $e->{proof} }) {
    my $mk = is_object($proof) ? _method_key($proof->{verificationMethod}) : undef;
    _fail('invalid-proof', $n) unless defined $mk;
    _fail('unauthorized-key', $n) unless $authorised{$mk};
    _fail('invalid-proof', $n) unless verify($document, $proof);
  }
  my ($number, $hash) = $e->{versionId} =~ /\A([1-9][0-9]*)-([^-]+)\z/;
  _fail('invalid-version-id', $n) unless defined $number && $number == $n;
  my $status = _check_hash($hash);
  _fail('invalid-version-id', $n) if $status eq 'not-base58';
  _fail('invalid-hash-algorithm', $n) unless $status eq 'ok';
  _fail('entry-hash-mismatch', $n)
    unless entry_hash($e, $previous ? $previous->{e}{versionId} : $p->{scid}) eq $hash;
  my $t = _time($e->{versionTime});
  _fail('invalid-version-time', $n) unless defined $t && (!$previous || $t > $previous->{time});
  _fail('future-version-time', $n) if $t > $now + 300;
  unless ($previous) {
    my $id = $p->{scid};
    $status = _check_hash($id);
    _fail('invalid-hash-algorithm', $n) if $status eq 'unsupported-algorithm';
    _fail('scid-mismatch', $n) unless $status eq 'ok';
    my $text = jcs({ %{ _without($e, 'proof') }, versionId => '{SCID}' });
    $text =~ s/\Q$id\E/{SCID}/g;
    _fail('scid-mismatch', $n) unless scid(parse($text)) eq $id;
  }
  return { e => $e, p => $p, n => $n, time => $t, rule => $rule };
}

sub _report { VH::Log::Error->new(@_)->report }

sub _verify_log {
  my ($log, $has_witness, $witness, $now) = @_;
  my $lines = _lines($log);
  my @entries;
  my $failure;
  return { entries => [], lines => $lines, failure => _report('invalid-log') } unless @$lines;
  for my $i (0 .. $#$lines) {
    my $ok = eval {
      my $e = eval { parse($lines->[$i]) };
      _fail('invalid-log', $i + 1) unless is_object($e);
      push @entries, _verify_entry($e, $entries[-1], $now);
      1;
    };
    next if $ok;
    my $error = $@;
    die $error unless blessed $error && $error->isa('VH::Log::Error');
    $failure = $error->report;
    last;
  }
  for my $i (0 .. $#entries) {
    my $rule = $entries[$i]{rule} or next;
    my $file = $has_witness ? $witness : [];
    my $code;
    if (!is_array($file) || grep { !(is_object($_) && is_string($_->{versionId}) && is_array($_->{proof})) } @$file) {
      $code = 'invalid-witness-file';
    } else {
      my %allowed = map { Unicode::Normalize::NFC($_->{id}) => 1 } @{ $rule->{witnesses} };
      my %index;
      $index{ $entries[$_]{e}{versionId} } //= $_ for 0 .. $#entries;
      my %approved;
      for my $record (@$file) {
        my $at = $index{ $record->{versionId} };
        next unless defined $at && $at >= $i;
        for my $proof (@{ $record->{proof} }) {
          my $mk = is_object($proof) ? _method_key($proof->{verificationMethod}) : undef;
          next unless defined $mk;
          my $id = Unicode::Normalize::NFC("did:key:$mk");
          $approved{$id} = 1 if $allowed{$id} && verify({ versionId => $record->{versionId} }, $proof);
        }
      }
      $code = 'witness-threshold-not-met' if keys(%approved) < $rule->{threshold};
    }
    if ($code) {
      $failure = _report($code, $i + 1);
      splice @entries, $i;
      last;
    }
  }
  return { entries => \@entries, lines => $lines, failure => $failure };
}

sub _line_value { my $line = shift; defined $line ? eval { parse($line) } : undef }

sub _line_id {
  my $v = _line_value(shift);
  return is_object($v) && is_string($v->{versionId}) ? $v->{versionId} : undef;
}

sub _retained {
  my ($v, $source, $id, $warnings) = @_;
  _fail('invalid-option') unless is_string($id) && $id =~ /\A([1-9][0-9]*)-/;
  my $n = $1;
  if (@{ $v->{entries} } < $n) {
    push @$warnings, { code => 'retained-version-not-found', message => 'retained version not found' };
  } elsif ($v->{entries}[$n - 1]{e}{versionId} ne $id) {
    my $k = $n + 0;
    _fail('fork-detected', $k, { version => $k, copies => [
      { source => 'retained', versionId => $id },
      { source => $source, versionId => $v->{entries}[$n - 1]{e}{versionId} }] });
  }
}

sub _result {
  my ($v, $options, $warnings, $copies) = @_;
  my ($entries, $lines, $failure) = @$v{qw(entries lines failure)};
  my $target;
  if (exists $options->{versionId}) {
    ($target) = grep { $_->{e}{versionId} eq $options->{versionId} } @$entries;
    if (!$target && grep { my $id = _line_id($_); defined $id && $id eq $options->{versionId} } @$lines[@$entries .. $#$lines]) {
      _fail($failure->{code}, $failure->{version});
    }
  } elsif (exists $options->{versionNumber}) {
    my $n = int $options->{versionNumber};
    $target = $entries->[$n - 1] if $n <= @$entries;
    _fail($failure->{code}, $failure->{version}) if !$target && $n <= @$lines;
  } elsif (exists $options->{versionTime}) {
    my $t = _time($options->{versionTime});
    if ($failure) {
      my $e = _line_value($lines->[scalar @$entries]);
      my $invalid_time = is_object($e) ? _time($e->{versionTime}) : undef;
      _fail($failure->{code}, $failure->{version}) if defined $invalid_time && $invalid_time <= $t;
    }
    ($target) = grep { $_->{time} <= $t } reverse @$entries;
  } else {
    $target = $entries->[-1];
  }
  _fail('not-found') unless $target;
  my ($first, $last) = ($entries->[0], $entries->[-1]);
  push @$warnings, { code => 'invalid-entries', message => $failure->{message} } if $failure;
  my %metadata = (
    versionId => $target->{e}{versionId}, versionTime => $target->{e}{versionTime},
    versionNumber => $target->{n}, created => $first->{e}{versionTime},
    updated => $last->{e}{versionTime}, scid => $first->{p}{scid},
    deactivated => $last->{p}{deactivated}, ttl => $last->{p}{ttl}, witness => $last->{p}{witness},
    watchers => $last->{p}{watchers}, updateKeys => $target->{p}{updateKeys},
    nextKeyHashes => $target->{p}{nextKeyHashes}, warnings => $warnings);
  $metadata{copies} = $copies if $copies;
  return { valid => true, state => $target->{e}{state}, metadata => \%metadata,
    firstInvalidVersion => $failure ? @$entries + 1 : undef, error => $failure };
}

sub _resolve_copies {
  my ($input, $now, $options) = @_;
  my @all = ({ source => 'primary', log => $input->{log}, exists $input->{witness} ? (witness => $input->{witness}) : () },
    @{ $input->{copies} // [] });
  croak 'copies must be objects' if grep { !is_object($_) } @all;
  my (@warnings, %status, %cache);
  my $get = sub {
    my $i = shift;
    $cache{$i} //= _verify_log($all[$i]{log}, exists $all[$i]{witness}, $all[$i]{witness}, $now);
  };
  my $invalid = sub {
    my $i = shift;
    $status{$i} = 'invalid';
    push @warnings, { code => 'copy-invalid', source => $all[$i]{source}, message => 'copy fails verification' };
  };
  for my $i (0 .. $#all) {
    next unless exists $all[$i]{unavailable};
    $status{$i} = 'unavailable';
    push @warnings, { code => 'copy-unavailable', source => $all[$i]{source}, message => $all[$i]{unavailable} };
  }
  my $ref;
  for my $i (0 .. $#all) {
    next if exists $status{$i};
    if (!$get->($i)->{failure}) { $ref = $i; last }
    $invalid->($i);
  }
  return { valid => false, error => $get->(0)->{failure} } unless defined $ref;
  my %matched = ($ref => 1);
  for my $i (0 .. $#all) {
    next if exists $status{$i} || $matched{$i};
    my ($r, $c) = ($get->($ref), $get->($i));
    my ($rl, $cl) = ($r->{lines}, $c->{lines});
    if (!@$cl) { $invalid->($i); next }
    my $last_id = _line_id($cl->[-1]);
    my $same = @$cl <= @$rl && defined $last_id && $last_id eq $r->{entries}[$#$cl]{e}{versionId};
    my $joint = @$cl > @$rl ? _line_id($cl->[$#$rl]) : undef;
    my $extends = @$cl > @$rl && defined $joint && $joint eq $r->{entries}[-1]{e}{versionId};
    if ($same) {
      $matched{$i} = 1;
    } elsif ($extends && !$c->{failure}) {
      $matched{$i} = 1;
      $ref = $i;
    } elsif ($c->{failure}) {
      $invalid->($i);
    } else {
      my $min = @$rl < @$cl ? scalar @$rl : scalar @$cl;
      my ($k) = grep { (_line_id($rl->[$_]) // "\0none") ne (_line_id($cl->[$_]) // "\0none") } 0 .. $min - 1;
      $k //= $min;
      _fail('fork-detected', $k + 1, { version => $k + 1, copies => [
        { source => $all[$ref]{source}, versionId => _line_id($rl->[$k]) // '' },
        { source => $all[$i]{source}, versionId => _line_id($cl->[$k]) // '' }] });
    }
  }
  my $r = $get->($ref);
  _retained($r, $all[$ref]{source}, $input->{retainedVersionId}, \@warnings) if exists $input->{retainedVersionId};
  my @copies;
  for my $i (0 .. $#all) {
    my %report = (source => $all[$i]{source});
    if (exists $status{$i}) {
      $report{status} = $status{$i};
      if ($status{$i} ne 'unavailable') {
        my $id = _line_id($get->($i)->{lines}[-1]);
        $report{versionId} = $id if defined $id;
      }
    } else {
      my $ls = $get->($i)->{lines};
      my $behind = @$ls < @{ $r->{lines} };
      $report{status} = $behind ? 'behind' : 'current';
      $report{versionId} = _line_id($ls->[-1]);
      push @warnings, { code => 'copy-behind', source => $all[$i]{source}, message => 'copy is behind' } if $behind;
    }
    push @copies, \%report;
  }
  my $min_copies = exists $options->{minCopies} ? $options->{minCopies} : 1;
  _fail('min-copies-not-met') if (grep { $_->{status} eq 'current' || $_->{status} eq 'behind' } @copies) < $min_copies;
  return _result($r, $options, \@warnings, \@copies);
}

# Resolves a log (see docs/interop-protocol.md for input and result shapes).
# Verification failures are reported in the result, never thrown.
sub resolve {
  my $input = shift;
  my $result = eval {
    my $now = _time($input->{now});
    _fail('invalid-option') unless defined $now;
    my $options = $input->{options} // {};
    _fail('invalid-option') unless is_object($options);
    my %allowed = map { $_ => 1 } qw(versionId versionTime versionNumber minCopies);
    _fail('invalid-option') if grep { !$allowed{$_} } keys %$options;
    _fail('invalid-option') if (grep { exists $options->{$_} } qw(versionId versionTime versionNumber)) > 1;
    _fail('invalid-option') if exists $options->{versionId} && !is_string($options->{versionId});
    _fail('invalid-option') if exists $options->{versionTime} && !defined _time($options->{versionTime});
    for (qw(versionNumber minCopies)) {
      _fail('invalid-option') if exists $options->{$_} && (!_integer($options->{$_}) || $options->{$_} < 1);
    }
    return _resolve_copies($input, $now, $options) if exists $input->{copies} || ($options->{minCopies} // 1) > 1;
    my $v = _verify_log($input->{log}, exists $input->{witness}, $input->{witness}, $now);
    return { valid => false, error => $v->{failure} } unless @{ $v->{entries} };
    my @warnings;
    _retained($v, 'primary', $input->{retainedVersionId}, \@warnings) if exists $input->{retainedVersionId};
    _result($v, $options, \@warnings);
  };
  return $result if $result;
  my $error = $@;
  die $error unless blessed $error && $error->isa('VH::Log::Error');
  return { valid => false, error => $error->report };
}

# The driver protocol's operations (docs/interop-protocol.md).
sub dispatch {
  my ($op, $input) = @_;
  croak 'input must be an object' unless is_object($input);
  croak 'op must be a string' unless is_string($op);
  return { output => jcs(parse($input->{text})) } if $op eq 'jcs';
  if ($op eq 'hash' || $op eq 'key-hash') {
    my $data = $input->{ $op eq 'hash' ? 'data' : 'multikey' };
    croak 'input must be a string' unless is_string($data);
    return { output => hash_b58($data) };
  }
  return { multikey => multikey($input->{seed}) } if $op eq 'multikey';
  return { scid => scid($input->{entry}) } if $op eq 'scid';
  return { hash => entry_hash($input->{entry}, $input->{previousVersionId}) } if $op eq 'entry-hash';
  return { proof => sign($input->{document}, $input->{seed}, $input) } if $op eq 'sign';
  return { valid => verify($input->{document}, $input->{proof}) ? true : false } if $op eq 'verify';
  return { proof => witness_proof($input->{versionId}, $input->{seed}, $input) } if $op eq 'witness';
  return create($input) if $op eq 'create';
  return update($input) if $op eq 'update';
  return resolve($input) if $op eq 'resolve';
  croak "unknown operation $op";
}

1;
