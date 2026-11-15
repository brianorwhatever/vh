package VH::Log::DidVh;
# did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
# verification as a VH-Log log, so it is verified by VH::Log with the did:vh
# specialisation. This module adds the DID syntax, the srcLog/srcWitness and
# DID URL rules, the resolution options, and DID Resolution metadata and errors.
use strict;
use warnings;
use Carp qw(croak);
use POSIX ();
use Scalar::Util qw(blessed);
use VH::Log ();
use VH::Log::JSON qw(decode_utf8 is_number is_string is_bool is_object is_array true false);
use Exporter 'import';

our @EXPORT_OK = qw(parse_did specialisation create_did update_did check_ref src_references parse_did_url resolve_did);

our $METHOD = 'did:vh:1.0';
our $PREFIX = 'did:vh:';
my $METHOD_SYNTAX = qr/\Adid:vh:(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\z/;
# Unicode White_Space (profile §3).
my $WHITESPACE = qr/[\x{9}-\x{D}\x{20}\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]/;
my @SELECTORS = qw(versionId versionTime versionNumber);
my %URL_PARAMETER = map { $_ => 1 } qw(src versionId versionTime versionNumber);
my %OPTION_ONLY = map { $_ => 1 } qw(didLog didWitness srcLog srcWitness checkWatchers extraWatchers minCopies includeDidLog);
my %ERROR_MAP = ('not-found' => 'notFound', 'invalid-option' => 'invalidOptions', 'fork-detected' => 'logForked',
  'min-copies-not-met' => 'insufficientCopies', 'unsupported-log-version' => 'featureNotSupported');

# A did:vh error: a DID Resolution error code, the message, and the VH-Log
# error report behind it, if any.
package VH::Log::DidVh::Error {
  sub new { my ($class, $code, $message, $vh_log) = @_; bless { code => $code, message => $message, vh_log => $vh_log }, $class }
  sub code { $_[0]{code} }
}

sub _error { die VH::Log::DidVh::Error->new(@_) }

# The SCID of a did:vh DID, or undef if $did does not match the ABNF.
sub parse_did {
  my $did = shift;
  return undef unless is_string($did) && $did =~ /\Adid:vh:([1-9A-HJ-NP-Za-km-z]{46})\z/;
  return $1;
}

# The did:vh specialisation: `method` instead of `logVersion`, a closed
# parameter set, and state.id = did:vh:<SCID> in every entry. With
# $expected_scid, the log's SCID must also be that of the DID being resolved.
sub specialisation {
  my $expected_scid = shift;
  my $state = sub {
    my ($s, $scid, $n) = @_;
    die VH::Log::Error->new('invalid-state', $n) if defined $expected_scid && $scid ne $expected_scid;
    die VH::Log::Error->new('invalid-state', $n) unless is_string($s->{id}) && $s->{id} eq $PREFIX . $scid;
  };
  return { param => 'method', versions => [$METHOD], syntax => $METHOD_SYNTAX, extra => [], state => $state };
}

# Creates a did:vh DID log. `method` and `scid` are added to the parameters if absent.
sub create_did {
  my $input = shift;
  my $created = VH::Log::create({ state => $input->{document}, parameters => $input->{parameters} // {},
    versionTime => $input->{versionTime}, signers => $input->{signers} }, 'method', $METHOD);
  return { log => $created->{log}, did => $PREFIX . $created->{scid}, scid => $created->{scid}, versionId => $created->{versionId} };
}

# Appends an entry; deactivate with parameters {"deactivated": true}.
sub update_did {
  my $input = shift;
  return VH::Log::update({ log => $input->{log}, state => $input->{document}, parameters => $input->{parameters} // {},
    versionTime => $input->{versionTime}, signers => $input->{signers} });
}

# ------------------------------------------------------------ shared URL checks

# Percent-decodes $s as UTF-8, or undef if an escape or the UTF-8 is malformed.
sub percent_decode {
  my $s = shift;
  utf8::encode($s);
  return undef if $s =~ /%(?![0-9A-Fa-f]{2})/;
  $s =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
  return eval { decode_utf8($s) };
}

sub _is_loopback_host {
  my $host = shift;
  return 1 if $host eq 'localhost' || $host eq '[::1]';
  my @parts = split /\./, $host, -1;
  return @parts == 4 && $parts[0] eq '127' && !grep { !(/\A(?:0|[1-9][0-9]{0,2})\z/ && $_ <= 255) } @parts;
}

sub _is_domain_name {
  my $host = shift;
  (my $name = $host) =~ s/\.\z//;
  return 0 if $name eq '' || length $name > 253;
  my @labels = split /\./, $name, -1;
  return 0 if $labels[-1] =~ /\A[0-9]+\z/;    # an IPv4 literal, or ends in a number
  return !grep { !/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/ } @labels;
}

# Splits scheme:rest (profile §3 steps 1–2); empty unless printable ASCII with a scheme.
sub _split_scheme {
  my $value = shift;
  return () unless is_string($value) && $value =~ /\A[\x21-\x7e]+\z/;
  return () unless $value =~ /\A([A-Za-z][A-Za-z0-9+.-]*):(.*)\z/s;
  return (lc $1, $2);
}

# Checks an http(s) authority (profile §3); returns the lowercased host, or undef.
sub _check_authority {
  my ($authority, $scheme) = @_;
  return undef if index($authority, '@') >= 0;
  my ($host, $port);
  if ($authority =~ /\A\[/) {
    my $close = index $authority, ']';
    return undef if $close < 0;
    $host = substr $authority, 0, $close + 1;
    my $after = substr $authority, $close + 1;
    if ($after ne '') {
      return undef unless $after =~ /\A:/;
      $port = substr $after, 1;
    }
  } else {
    my $colon = index $authority, ':';
    $host = $colon < 0 ? $authority : substr $authority, 0, $colon;
    $port = substr $authority, $colon + 1 if $colon >= 0;
  }
  $host = lc $host;
  return undef if defined $port && !($port =~ /\A[0-9]{1,5}\z/ && $port <= 65535);
  return _is_loopback_host($host) ? $host : undef if $scheme eq 'http';
  return $host !~ /\A\[/ && _is_domain_name($host) ? $host : undef;
}

# Checks the segments of a path starting with "/" (profile §3). With $strict
# (the src DID URL parameter), segments must also be non-empty and not start or
# end with whitespace.
sub _segments_ok {
  my ($path, $strict) = @_;
  my @segments = split m{/}, substr($path, 1), -1;
  for my $raw (@segments ? @segments : ('')) {
    my $segment = percent_decode($raw);
    return 0 if !defined $segment || $segment eq '.' || $segment eq '..' || $segment =~ m{[/\\\x00]};
    return 0 if $strict && ($segment eq '' || $segment =~ /\A$WHITESPACE/ || $segment =~ /$WHITESPACE\z/);
  }
  return 1;
}

# ------------------------------------------------------------ references

# Validates a srcLog or srcWitness reference (profile §3.1) and returns its
# kind: web, loopback, file or other. Dies with invalidOptions.
sub check_ref {
  my $ref = shift;
  my $invalid = sub { _error('invalidOptions', "invalid reference: $_[0]") };
  my ($scheme, $rest) = _split_scheme($ref);
  $invalid->('not a printable-ASCII absolute URL') unless defined $scheme;
  $invalid->('must not have a fragment') if index($rest, '#') >= 0;
  if ($scheme eq 'https' || $scheme eq 'http') {
    $invalid->('missing authority') unless $rest =~ m{\A//};
    my ($authority, $after) = substr($rest, 2) =~ m{\A([^/?]*)(.*)\z}s;
    my ($path) = $after =~ /\A([^?]*)/;
    $invalid->('invalid host') unless defined _check_authority($authority, $scheme);
    $invalid->('must have a path') if $path eq '';
    $invalid->('invalid path segment') unless _segments_ok($path, 0);
    return $scheme eq 'http' ? 'loopback' : 'web';
  }
  if ($scheme eq 'file') {
    $invalid->('must not have a query') if index($rest, '?') >= 0;
    my $path;
    if ($rest =~ m{\A//}) {
      my $slash = index $rest, '/', 2;
      $invalid->('file URL needs an absolute path') if $slash < 0;
      my $host = lc substr $rest, 2, $slash - 2;
      $invalid->('file URL host must be empty or localhost') unless $host eq '' || $host eq 'localhost';
      $path = substr $rest, $slash;
    } else {
      $invalid->('file URL needs an absolute path') unless $rest =~ m{\A/};
      $path = $rest;
    }
    $invalid->('invalid path segment') unless _segments_ok($path, 0);
    return 'file';
  }
  $invalid->('empty URL') if $rest eq '';
  return 'other';
}

# Validates a (percent-decoded) src DID URL parameter and derives srcLog and
# srcWitness from it (profile §3.2). Dies with invalidDidUrl.
sub src_references {
  my $src = shift;
  my $invalid = sub { _error('invalidDidUrl', "invalid src: $_[0]") };
  my ($scheme, $rest) = _split_scheme($src);
  $invalid->('not a printable-ASCII absolute URL') unless defined $scheme;
  $invalid->('must not have a query or fragment') if $rest =~ /[?#]/;
  $invalid->("$scheme is not allowed in a DID URL") if $scheme eq 'http' || $scheme eq 'file';
  $invalid->('not a hierarchical URL with an authority') unless $rest =~ m{\A//[^/]};
  (my $base = $rest) =~ s{/\z}{};
  if ($scheme eq 'https') {
    my ($authority, $path) = substr($base, 2) =~ m{\A([^/]*)(.*)\z}s;
    $invalid->('invalid https host') unless defined _check_authority($authority, 'https');
    $invalid->('invalid path segment') unless $path eq '' || _segments_ok($path, 1);
  }
  my $location = "$scheme:$base";
  return { srcLog => "$location/did.jsonl", srcWitness => "$location/did-witness.json" };
}

# Parses a did:vh DID URL as a dereferencer does (profile §4); returns
# {did, options, fragment?}. Dies with invalidDidUrl.
sub parse_did_url {
  my $did_url = shift;
  my $invalid = sub { _error('invalidDidUrl', "invalid DID URL: $_[0]") };
  $invalid->('not a string') unless is_string($did_url);
  my $hash = index $did_url, '#';
  my $before_fragment = $hash < 0 ? $did_url : substr $did_url, 0, $hash;
  my $q = index $before_fragment, '?';
  my $did = $q < 0 ? $before_fragment : substr $before_fragment, 0, $q;
  $invalid->('not a did:vh DID') unless defined parse_did($did);
  my (%seen, %options);
  if ($q >= 0) {
    for my $pair (split /&/, substr($before_fragment, $q + 1), -1) {
      my $eq = index $pair, '=';
      $invalid->('query parameter has no value') if $eq < 0;
      my ($key, $value) = (percent_decode(substr $pair, 0, $eq), percent_decode(substr $pair, $eq + 1));
      $invalid->('malformed percent-encoding') unless defined $key && defined $value;
      $invalid->("$key is a resolution option, not a DID URL parameter") if $OPTION_ONLY{$key};
      next unless $URL_PARAMETER{$key};
      $invalid->("$key given more than once") if $seen{$key}++;
      if ($key eq 'src') {
        %options = (%options, %{ src_references($value) });
      } elsif ($key eq 'versionNumber') {
        $invalid->('versionNumber must be a positive integer') unless $value =~ /\A[1-9][0-9]{0,15}\z/;
        $options{versionNumber} = 0 + $value;
      } else {
        $options{$key} = $value;
      }
    }
  }
  my %result = (did => $did, options => \%options);
  $result{fragment} = substr $did_url, $hash + 1 if $hash >= 0;
  return \%result;
}

# ------------------------------------------------------------ resolve

sub _integer { my $v = shift; is_number($v) && $v == $v && $v - $v == 0 && $v == int($v) }

sub _positive_integer { my $v = shift; _integer($v) && $v >= 1 }

# did:vh resolution options validation (profile §5, step 2).
sub _validate_options {
  my ($o, $remote) = @_;
  my $invalid = sub { _error('invalidOptions', $_[0]) };
  $invalid->('resolution options must be an object') unless is_object($o);
  $invalid->('exactly one of didLog and srcLog must be given') if !!exists $o->{didLog} == !!exists $o->{srcLog};
  $invalid->('at most one of didWitness and srcWitness may be given') if exists $o->{didWitness} && exists $o->{srcWitness};
  $invalid->('didLog must be a string') if exists $o->{didLog} && !is_string($o->{didLog});
  $invalid->('didWitness must be an array') if exists $o->{didWitness} && !is_array($o->{didWitness});
  for my $key (qw(srcLog srcWitness)) {
    next unless exists $o->{$key};
    my $kind = check_ref($o->{$key});
    $invalid->("$key: a resolver that serves other systems must not use local references")
      if $remote && ($kind eq 'file' || $kind eq 'loopback');
  }
  $invalid->('at most one version selector may be given') if (grep { exists $o->{$_} } @SELECTORS) > 1;
  $invalid->('versionId must be a string') if exists $o->{versionId} && !is_string($o->{versionId});
  $invalid->('versionTime must be a whole-second UTC ISO 8601 time')
    if exists $o->{versionTime} && !defined VH::Log::_time($o->{versionTime});
  $invalid->('versionNumber must be a positive integer') if exists $o->{versionNumber} && !_positive_integer($o->{versionNumber});
  if (exists $o->{checkWatchers}) {
    my $c = $o->{checkWatchers};
    $invalid->('checkWatchers must be a non-negative integer or "all"')
      unless (is_string($c) && $c eq 'all') || (_integer($c) && $c >= 0);
  }
  if (exists $o->{extraWatchers}) {
    my $w = $o->{extraWatchers};
    $invalid->('extraWatchers must be an array of https URLs')
      unless is_array($w) && !grep { !(is_string($_) && /\A[\x21-\x7e]+\z/ && m{\Ahttps://[^/?#]}) } @$w;
  }
  $invalid->('minCopies must be a positive integer') if exists $o->{minCopies} && !_positive_integer($o->{minCopies});
  $invalid->('includeDidLog must be a boolean') if exists $o->{includeDidLog} && !is_bool($o->{includeDidLog});
  return $o;
}

sub _failure {
  my $e = shift;
  my %details = (title => $e->{code}, detail => $e->{message});
  $details{vhLog} = $e->{vh_log} if $e->{vh_log};
  return { didResolutionMetadata => { error => $e->{code}, problemDetails => \%details }, didDocument => undef,
    didDocumentMetadata => {} };
}

sub _current_time { POSIX::strftime('%Y-%m-%dT%H:%M:%SZ', gmtime) }

# did:vh resolve(did, resolutionOptions) (profile §5). Offline: it verifies a
# log passed in didLog (and didWitness), and returns featureNotSupported when
# it would have to retrieve anything. $context may set now (the resolver's
# clock, a versionTime string) and remote.
sub resolve_did {
  my ($did, $options, $context) = @_;
  $context //= {};
  my $result = eval {
    my $scid = parse_did($did);
    _error('invalidDid', 'not a did:vh DID') unless defined $scid;
    my $o = _validate_options($options // {}, $context->{remote});
    _error('featureNotSupported', 'this resolver does not retrieve srcLog references') if exists $o->{srcLog};
    my $check = $o->{checkWatchers};
    if ((defined $check && !(is_number($check) && $check == 0)) || @{ $o->{extraWatchers} // [] }) {
      _error('featureNotSupported', 'this resolver does not retrieve copies from watchers');
    }
    my $spec = specialisation($scid);
    my $now = $context->{now} // _current_time();
    my $log = $o->{didLog};
    # Whether the log needs witnessing does not depend on the witness file.
    # Without one, the first entry that needs it fails, which cuts it from entries.
    my $clock = VH::Log::_time($now) // VH::Log::_time(_current_time());
    my $unwitnessed = VH::Log::_verify_log($log, 0, undef, $clock, $spec);
    my $witnessed = ($unwitnessed->{failure} && $unwitnessed->{failure}{code} eq 'witness-threshold-not-met')
      || grep { $_->{rule} } @{ $unwitnessed->{entries} };
    _error('featureNotSupported', 'this resolver does not retrieve srcWitness references') if $witnessed && exists $o->{srcWitness};
    my %vh_options = map { exists $o->{$_} ? ($_ => $o->{$_}) : () } @SELECTORS, 'minCopies';
    my %request = (log => $log, now => $now, options => \%vh_options);
    $request{witness} = $o->{didWitness} if exists $o->{didWitness};
    my $r = VH::Log::resolve(\%request, $spec);
    unless ($r->{valid}) {
      my $error = $r->{error};
      _error($ERROR_MAP{ $error->{code} } // 'invalidDid', $error->{message}, $error);
    }
    my $partial = $r->{error};
    if (!(grep { exists $o->{$_} } @SELECTORS) && $partial && $partial->{code} eq 'unsupported-log-version') {
      # Entries after the last valid one may change the document or its keys (profile §5).
      _error('featureNotSupported', $partial->{message}, $partial);
    }
    my $m = $r->{metadata};
    # A deactivated DID's document is not returned; earlier versions still are (profile §5).
    my $is_last = $m->{versionTime} eq $m->{updated};
    my %metadata = map { $_ => $m->{$_} } qw(versionId versionTime created updated scid deactivated ttl watchers);
    $metadata{witness} = $m->{witness} if $m->{witness};
    my %meta = (contentType => 'application/did+json');
    $meta{warnings} = $m->{warnings} if @{ $m->{warnings} };
    if (is_bool($o->{includeDidLog}) && $o->{includeDidLog}) {
      my @lines = @{ VH::Log::_lines($log) };
      my $valid = defined $r->{firstInvalidVersion} ? $r->{firstInvalidVersion} - 1 : scalar @lines;
      $meta{didLog} = join '', map { "$_\n" } @lines[0 .. $valid - 1];
      $meta{didWitness} = $o->{didWitness} // [] if $witnessed;
    }
    +{ didResolutionMetadata => \%meta, didDocument => $m->{deactivated} && $is_last ? undef : $r->{state},
      didDocumentMetadata => \%metadata };
  };
  return $result if $result;
  my $error = $@;
  die $error unless blessed $error && $error->isa('VH::Log::DidVh::Error');
  return _failure($error);
}

# Runs $fn, turning a did:vh error into {valid: false, error}.
sub _rejected {
  my $fn = shift;
  my $result = eval { +{ valid => true, %{ $fn->() } } };
  return $result if $result;
  my $error = $@;
  die $error unless blessed $error && $error->isa('VH::Log::DidVh::Error');
  return { valid => false, error => $error->{code} };
}

# The didvh-* driver operations (docs/interop-protocol.md, "did:vh operations").
sub dispatch {
  my ($op, $input) = @_;
  return create_did($input) if $op eq 'didvh-create';
  return update_did($input) if $op eq 'didvh-update';
  if ($op eq 'didvh-resolve') {
    my $remote = is_bool($input->{remote}) && $input->{remote};
    return resolve_did($input->{did}, $input->{options}, { now => $input->{now}, remote => $remote });
  }
  return _rejected(sub { +{ kind => check_ref($input->{ref}) } }) if $op eq 'didvh-ref';
  return _rejected(sub { src_references($input->{src}) }) if $op eq 'didvh-src';
  return _rejected(sub { parse_did_url($input->{didUrl}) }) if $op eq 'didvh-did-url';
  croak "unknown operation $op";
}

1;
