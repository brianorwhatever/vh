package VH::Log::JSON;
# Strict I-JSON parsing and RFC 8785 (JCS) serialisation for VH::Log.
#
# Value model (the same conventions as JSON::PP):
#   object  => HASH ref          array => ARRAY ref
#   string  => scalar created as a string
#   number  => scalar created as a number (parsed numbers are binary64 NVs)
#   boolean => JSON::PP::Boolean ($JSON::PP::true / $JSON::PP::false)
#   null    => undef
use strict;
use warnings;
no warnings 'recursion';
use B ();
use Carp qw(croak);
use JSON::PP ();
use Exporter 'import';

our $VERSION = '0.1.0';
our @EXPORT_OK = qw(decode_json decode_utf8 canonicalize format_number is_number is_string
  is_bool is_object is_array true false);

sub true  () { $JSON::PP::true }
sub false () { $JSON::PP::false }

# A scalar is a number if Perl created it as one. Stringifying a number makes
# it look like a string on Perl < 5.36, so the library never does that to
# caller data before checking its type.
sub is_number {
  my $v = shift;
  return 0 if !defined $v || ref $v;
  my $flags = B::svref_2object(\$v)->FLAGS;
  return ($flags & (B::SVp_IOK | B::SVp_NOK)) && !($flags & B::SVp_POK) ? 1 : 0;
}
sub is_string { my $v = shift; defined $v && !ref $v && !is_number($v) ? 1 : 0 }
sub is_bool {
  my $v = shift;
  return 1 if JSON::PP::is_bool($v);
  return ref $v eq 'SCALAR' && defined $$v && !ref $$v && ($$v eq '1' || $$v eq '0') ? 1 : 0;
}
sub is_object { ref $_[0] eq 'HASH' ? 1 : 0 }
sub is_array  { ref $_[0] eq 'ARRAY' ? 1 : 0 }

# ---------------------------------------------------------------- parsing

# Decodes RFC 3629 UTF-8 bytes. Noncharacters such as U+FFFF are allowed;
# overlong forms, surrogates and code points above U+10FFFF are not.
sub decode_utf8 {
  my $text = shift;
  croak 'invalid UTF-8' unless utf8::decode($text);
  croak 'invalid UTF-8' if $text =~ /[\x{D800}-\x{DFFF}]|[^\x{0}-\x{10FFFF}]/;
  return $text;
}

my %UNESCAPE = ('"' => '"', '\\' => '\\', '/' => '/', b => "\b", f => "\f", n => "\n", r => "\r", t => "\t");

# Parses a JSON text (a Perl character string). Dies on anything RFC 8259
# rejects and on what the profile forbids: non-finite numbers and lone
# surrogate escapes. Duplicate keys keep the last value.
sub decode_json {
  my $text = shift;
  croak 'JSON text must be a string' unless is_string($text);
  croak 'JSON text contains a surrogate code point' if $text =~ /[\x{D800}-\x{DFFF}]/;
  pos($text) = 0;
  _ws(\$text);
  my $value = _value(\$text);
  _ws(\$text);
  croak 'trailing characters after JSON value' if pos($text) < length $text;
  return $value;
}

sub _ws { ${$_[0]} =~ /\G[ \t\n\r]*/gc }

sub _value {
  my $t = shift;
  if ($$t =~ /\G"/gc) { return _string($t) }
  if ($$t =~ /\G\{/gc) {
    my %object;
    _ws($t);
    return \%object if $$t =~ /\G\}/gc;
    while (1) {
      croak 'expected object key' unless $$t =~ /\G"/gc;
      my $key = _string($t);
      _ws($t);
      croak q(expected ':') unless $$t =~ /\G:/gc;
      _ws($t);
      $object{$key} = _value($t);
      _ws($t);
      next if $$t =~ /\G,/gc && do { _ws($t); 1 };
      return \%object if $$t =~ /\G\}/gc;
      croak q(expected ',' or '}');
    }
  }
  if ($$t =~ /\G\[/gc) {
    my @array;
    _ws($t);
    return \@array if $$t =~ /\G\]/gc;
    while (1) {
      push @array, _value($t);
      _ws($t);
      next if $$t =~ /\G,/gc && do { _ws($t); 1 };
      return \@array if $$t =~ /\G\]/gc;
      croak q(expected ',' or ']');
    }
  }
  if ($$t =~ /\G(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)/gc) {
    return _number($1);
  }
  return true  if $$t =~ /\Gtrue/gc;
  return false if $$t =~ /\Gfalse/gc;
  return undef if $$t =~ /\Gnull/gc;
  croak 'unexpected character in JSON text';
}

# Every JSON number is an IEEE-754 binary64 value (RFC 8785 §3.2.2.3).
# A literal without '.', 'e' or 'E' would otherwise stay a 64-bit integer.
sub _number {
  my $literal = shift;
  $literal .= 'e0' unless $literal =~ /[.eE]/;
  my $n = 0 + $literal;
  croak 'number is not a finite binary64 value' if $n == 9**9**9 || $n == -9**9**9;
  return $n;
}

sub _string {
  my $t = shift;
  my $out = '';
  while (1) {
    if ($$t =~ /\G([^"\\\x00-\x1f]+)/gc) { $out .= $1; next }
    return $out if $$t =~ /\G"/gc;
    if ($$t =~ /\G\\(["\\\/bfnrt])/gc) { $out .= $UNESCAPE{$1}; next }
    if ($$t =~ /\G\\u([0-9a-fA-F]{4})/gc) {
      my $unit = hex $1;
      if ($unit >= 0xD800 && $unit <= 0xDBFF) {
        croak 'lone surrogate escape' unless $$t =~ /\G\\u([dD][c-fC-F][0-9a-fA-F]{2})/gc;
        $unit = 0x10000 + (($unit - 0xD800) << 10) + (hex($1) - 0xDC00);
      } elsif ($unit >= 0xDC00 && $unit <= 0xDFFF) {
        croak 'lone surrogate escape';
      }
      $out .= chr $unit;
      next;
    }
    croak 'invalid string in JSON text';
  }
}

# ---------------------------------------------------------- serialisation

my %ESCAPE = ('"' => '\\"', '\\' => '\\\\', "\b" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t');

sub _encode_string {
  my $s = shift;
  croak 'string contains a surrogate code point' if $s =~ /[\x{D800}-\x{DFFF}]/;
  $s =~ s/([\x00-\x1f"\\])/$ESCAPE{$1} \/\/ sprintf('\\u%04x', ord $1)/ge;
  return qq("$s");
}

# JCS sorts member names by UTF-16 code units; big-endian 16-bit units
# compare correctly as bytes.
sub _utf16_key {
  return pack 'n*', map {
    $_ < 0x10000 ? $_ : (0xD800 + (($_ - 0x10000) >> 10), 0xDC00 + (($_ - 0x10000) & 0x3FF))
  } unpack 'U*', shift;
}

# RFC 8785 serialisation, returned as a Perl character string. Encode it as
# UTF-8 before hashing.
sub canonicalize {
  my $v = shift;
  return 'null' unless defined $v;
  my $r = ref $v;
  if ($r eq 'HASH') {
    my @keys = map { $_->[0] } sort { $a->[1] cmp $b->[1] } map { [$_, _utf16_key($_)] } keys %$v;
    return '{' . join(',', map { _encode_string($_) . ':' . canonicalize($v->{$_}) } @keys) . '}';
  }
  return '[' . join(',', map { canonicalize($_) } @$v) . ']' if $r eq 'ARRAY';
  return (($r eq 'SCALAR' ? $$v : $v) ? 'true' : 'false') if is_bool($v);
  croak "cannot serialise a $r reference as JSON" if $r;
  return format_number($v) if is_number($v);
  return _encode_string($v);
}

# The ECMAScript Number-to-String algorithm used by RFC 8785: the shortest
# decimal that round-trips to the same binary64 value, choosing the closest
# when several have that length. sprintf('%.*e') rounds correctly, so the
# first precision whose correctly rounded value round-trips is the answer.
# At power-of-two boundaries the rounding interval is asymmetric, so the
# neighbouring candidate on the other side of the value is also tried.
sub format_number {
  # Perl may hold integers as exact 64-bit IVs; JCS needs their binary64 value.
  my $x = unpack 'd', pack 'd', shift;
  croak 'number is not finite' if $x != $x || $x == 9**9**9 || $x == -9**9**9;
  return '0' if $x == 0;
  my $sign = $x < 0 ? '-' : '';
  $x = -$x if $x < 0;
  my ($digits, $point);
  for my $precision (1 .. 17) {
    my ($mantissa, $e) = sprintf('%.*e', $precision - 1, $x) =~ /^([0-9.]+)e([-+][0-9]+)$/
      or croak 'unexpected sprintf output';
    (my $d = $mantissa) =~ tr/.//d;
    my $exponent = $e - $precision + 1;
    my $candidate = 0 + ($d . 'e' . $exponent);
    if ($candidate == $x) { ($digits, $point) = ($d, $e + 1); last }
    my $other = $candidate > $x ? $d - 1 : $d + 1;
    next if $other <= 0;
    if (0 + ($other . 'e' . $exponent) == $x) {
      $digits = sprintf '%d', $other;
      $point = length($digits) + $exponent;
      last;
    }
  }
  croak 'could not format number' unless defined $digits;
  $digits =~ s/0+$//;
  my $n = length $digits;
  my $text;
  if ($point >= $n && $point <= 21) {
    $text = $digits . ('0' x ($point - $n));
  } elsif ($point > 0 && $point <= 21) {
    $text = substr($digits, 0, $point) . '.' . substr($digits, $point);
  } elsif ($point <= 0 && $point > -6) {
    $text = '0.' . ('0' x -$point) . $digits;
  } else {
    my $power = $point - 1;
    $text = substr($digits, 0, 1) . ($n > 1 ? '.' . substr($digits, 1) : '')
      . 'e' . ($power >= 0 ? '+' : '-') . abs($power);
  }
  return $sign . $text;
}

1;
