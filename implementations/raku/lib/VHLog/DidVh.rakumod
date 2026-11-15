unit module VHLog::DidVh;
# did:vh (didvh-interop-0, docs/didvh-profile.md) on top of the VH-Log verifier.
use VHLog;
use VHLog::JSON;

class X::DidVh is Exception {
    has $.code;
    has $.detail;
    has $.vh-log;
    method message { $!detail }
}
sub fail-did($code, $detail, $vh-log?) { X::DidVh.new(:$code, :$detail, :$vh-log).throw }

# ---------------------------------------------------------------- DIDs

sub did-scid($did) is export {
    return Nil unless $did ~~ Str && $did ~~ /^ 'did:vh:' (<[1..9 A..H J..N P..Z a..k m..z]> ** 46) $/;
    ~$0
}
sub version-syntax($v) { so $v ~~ /^ 'did:vh:' [0 | <[1..9]> <[0..9]>*] '.' [0 | <[1..9]> <[0..9]>*] $/ }

# The specialisation for resolving did:vh:<scid>.
sub didvh-spec(Str $scid) is export {
    %(version-param => 'method', accepted => ['did:vh:1.0'], syntax => &version-syntax,
      closed => [<method scid updateKeys nextKeyHashes witness watchers deactivated ttl>],
      state-check => -> $log-scid, $state {
          $log-scid eq $scid && $state ~~ Associative && $state<id> ~~ Str && $state<id> eq "did:vh:$log-scid"
      })
}

# ---------------------------------------------------------------- text helpers

sub printable($s) { $s ~~ Str && $s.chars > 0 && so $s.ords.all ~~ 33..126 }
sub hexv($c) { 48 <= $c <= 57 ?? $c - 48 !! 65 <= $c <= 70 ?? $c - 55 !! 97 <= $c <= 102 ?? $c - 87 !! Nil }
# Percent-decodes a list of code points once; the bytes must be UTF-8.
sub pct(@c --> Str) {
    my @b;
    my $i = 0;
    while $i < @c.elems {
        if @c[$i] == 37 {
            die 'bad escape' unless $i + 2 < @c.elems && hexv(@c[$i+1]).defined && hexv(@c[$i+2]).defined;
            @b.push(hexv(@c[$i+1]) * 16 + hexv(@c[$i+2]));
            $i += 3;
        }
        else { @b.append(rawstr([@c[$i]]).encode('utf8-c8').list); $i++ }
    }
    my $s = Buf.new(@b).decode('utf8-c8');
    cps($s);    # dies unless the bytes are UTF-8
    $s
}
sub white-space($u) {
    so $u == any(0x09..0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000..0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000)
}
# A path segment of a reference; :strict adds the src rules.
sub segment(Str $seg, :$strict) {
    my $d = pct($seg.ords);
    die 'dot segment' if $d eq '.' || $d eq '..';
    my @c = cps($d);
    die 'bad character' if @c.grep({ $_ == 47 || $_ == 92 || $_ == 0 });
    if $strict {
        die 'empty segment' unless @c;
        die 'white space' if white-space(@c[0]) || white-space(@c[*-1]);
    }
}
sub split-scheme(Str $s) {
    my $m = $s ~~ /^ (<[A..Z a..z]> <[A..Z a..z 0..9 + . \-]>*) ':' (.*) $/;
    die 'no scheme' unless $m;
    ((~$m[0]).lc, ~$m[1])
}
# Host (lowercase) and whether it is an IP literal; checks the port.
sub host-port(Str $a) {
    die 'userinfo' if $a.contains('@');
    my ($host, $port);
    if $a.starts-with('[') {
        my $j = $a.index(']') // die 'IP literal';
        $host = $a.substr(0, $j + 1);
        my $rest = $a.substr($j + 1);
        if $rest ne '' { die 'port' unless $rest.starts-with(':'); $port = $rest.substr(1) }
    }
    else {
        my $j = $a.index(':');
        if $j.defined { $host = $a.substr(0, $j); $port = $a.substr($j + 1) } else { $host = $a }
    }
    die 'port' if $port.defined && !($port ~~ /^ <[0..9]> ** 1..5 $/ && $port.Int <= 65535);
    ($host.lc, $host.starts-with('['))
}
sub domain(Str $host) {
    my $h = $host.ends-with('.') ?? $host.chop !! $host;
    return False unless 1 <= $h.chars <= 253;
    my @labels = $h.split('.');
    for @labels { return False unless 1 <= .chars <= 63 && $_ ~~ /^ <[a..z 0..9]> [<[a..z 0..9 \-]>* <[a..z 0..9]>]? $/ }
    @labels[*-1] !~~ /^ <[0..9]>+ $/
}
sub loopback(Str $h) {
    return True if $h eq 'localhost' || $h eq '[::1]';
    my @o = $h.split('.');
    @o.elems == 4 && @o[0] eq '127'
        && so @o.map({ $_ ~~ /^ [0 | <[1..9]> <[0..9]> ** 0..2] $/ && .Int <= 255 }).all
}
sub path-segments(Str $path) { segment($_) for $path.substr(1).split('/') }

# ---------------------------------------------------------------- references

sub kind-of(Str $r) {
    my ($scheme, $rest) = split-scheme($r);
    if $scheme eq 'https' || $scheme eq 'http' {
        die 'authority' unless $rest.starts-with('//');
        my $x = $rest.substr(2);
        my $a = ($x.index('/'), $x.index('?'), $x.chars).grep(*.defined).min;
        my $after = $x.substr($a);
        my $path = $after.substr(0, $after.index('?') // $after.chars);
        my ($host, $literal) = host-port($x.substr(0, $a));
        if $scheme eq 'https' { die 'host' if $literal || !domain($host) }
        else { die 'host' unless loopback($host) }
        die 'path' if $path eq '';
        path-segments($path);
        return $scheme eq 'https' ?? 'web' !! 'loopback';
    }
    if $scheme eq 'file' {
        die 'query' if $rest.contains('?');
        my $path = $rest;
        if $rest.starts-with('//') {
            my $x = $rest.substr(2);
            my $j = $x.index('/') // $x.chars;
            my $host = $x.substr(0, $j).lc;
            die 'host' unless $host eq '' || $host eq 'localhost';
            $path = $x.substr($j);
        }
        die 'relative path' unless $path.starts-with('/');
        path-segments($path);
        return 'file';
    }
    die 'empty' if $rest eq '';
    'other'
}
# §3.1: a srcLog/srcWitness reference's kind (web, loopback, file, other), or Nil (invalidOptions).
sub reference-kind($r) is export {
    return Nil unless printable($r) && !$r.contains('#');
    try kind-of($r)
}

sub locations-of(Str $src) {
    die 'characters' unless printable($src) && !$src.contains('?') && !$src.contains('#');
    my ($scheme, $rest) = split-scheme($src);
    die 'scheme' if $scheme eq 'http' || $scheme eq 'file' || !$rest.starts-with('//');
    $rest = $rest.chop if $rest.ends-with('/');
    my $x = $rest.substr(2);
    my $j = $x.index('/') // $x.chars;
    my $authority = $x.substr(0, $j);
    my $path = $x.substr($j);
    die 'authority' if $authority eq '';
    if $scheme eq 'https' {
        my ($host, $literal) = host-port($authority);
        die 'host' if $literal || !domain($host);
        if $path ne '' { segment($_, :strict) for $path.substr(1).split('/') }
    }
    my $base = "$scheme:$rest";
    ["$base/did.jsonl", "$base/did-witness.json"]
}
# §3.2: [srcLog, srcWitness] from a percent-decoded src value, or Nil (invalidDidUrl).
sub src-locations($src) is export { $src ~~ Str ?? (try locations-of($src)) !! Nil }

# ---------------------------------------------------------------- DID URLs

constant RESOLUTION-OPTIONS = <didLog didWitness srcLog srcWitness checkWatchers extraWatchers minCopies includeDidLog>;

sub split-on(@c, $sep) {
    my @parts = [[],];
    for @c { if $_ == $sep { @parts.push([]) } else { @parts[*-1].push($_) } }
    @parts
}
sub did-url-of(Str $url) {
    my @c = cps($url);
    my $h = @c.first({ $_ == 35 }, :k);
    my $fragment = $h.defined ?? rawstr(@c[$h ^.. *]) !! Nil;
    my @before = $h.defined ?? @c[^$h] !! @c;
    my $q = @before.first({ $_ == 63 }, :k);
    my $did = rawstr($q.defined ?? @before[^$q] !! @before);
    die 'not a did:vh DID' unless did-scid($did).defined;
    my %options;
    my %seen;
    if $q.defined {
        for split-on(@before[$q ^.. *], 38) -> @part {
            my $i = @part.first({ $_ == 61 }, :k) // die 'no value';
            my $name = pct(@part[^$i]);
            my $value = pct(@part[$i ^.. *]);
            die 'resolution option' if $name eq any(RESOLUTION-OPTIONS);
            next unless $name eq any(<src versionId versionTime versionNumber>);
            die 'repeated' if %seen{$name}++;
            given $name {
                when 'src' {
                    my $l = src-locations($value) // die 'src';
                    %options<srcLog> = $l[0];
                    %options<srcWitness> = $l[1];
                }
                when 'versionNumber' {
                    die 'versionNumber' unless $value ~~ /^ <[1..9]> <[0..9]> ** 0..15 $/;
                    %options<versionNumber> = $value.Int;
                }
                default { %options{$name} = $value }
            }
        }
    }
    %(:$did, :%options, :$fragment)
}
# §4: {did, options, fragment} (fragment Nil without a '#'), or Nil (invalidDidUrl).
sub parse-did-url($url) is export { $url ~~ Str ?? (try did-url-of($url)) !! Nil }

# ---------------------------------------------------------------- generation

sub controller($input) {
    %(state => $input<document>, parameters => ($input<parameters> // {}),
      versionTime => $input<versionTime>, signers => $input<signers>)
}
# {document, parameters, versionTime, signers} -> {log, did, scid, versionId}
sub create-did($input) is export {
    my %out = create-log(controller($input), :defaults(method => 'did:vh:1.0', scid => '{SCID}'));
    %out<did> = "did:vh:%out<scid>";
    %out
}
# {log, document, parameters, versionTime, signers} -> {log, versionId}
sub update-did($input) is export {
    my %in = controller($input);
    %in<log> = $input<log>;
    update-log(%in)
}

# ---------------------------------------------------------------- resolution

sub error-code($code) {
    given $code {
        when 'not-found' { 'notFound' }
        when 'invalid-option' { 'invalidOptions' }
        when 'unsupported-log-version' { 'featureNotSupported' }
        when 'fork-detected' { 'logForked' }
        when 'min-copies-not-met' { 'insufficientCopies' }
        default { 'invalidDid' }
    }
}
sub integer-at-least($v, $min) { $v ~~ Numeric && $v !~~ Bool && $v == $v && $v.abs != Inf && $v == $v.floor && $v >= $min }
# The lines the VH-Log verifier reads: split on LF, trailing blank lines dropped.
sub log-lines(Str $log) {
    my @lines = $log.split("\n");
    @lines.pop while @lines && @lines[*-1].trim eq '';
    @lines
}
sub resolve-or-die($did, $options, $now, $remote) {
    my $scid = did-scid($did) // fail-did('invalidDid', 'not a did:vh DID');
    my &bad = -> $m { fail-did('invalidOptions', $m) };
    my &unsupported = -> $m { fail-did('featureNotSupported', $m) };
    bad('options must be an object') unless $options ~~ Associative;
    my $o = $options;
    my &has = -> $k { $o{$k}:exists };
    bad('exactly one of didLog and srcLog is required') if has('didLog') == has('srcLog');
    bad('didWitness and srcWitness are exclusive') if has('didWitness') && has('srcWitness');
    bad('didLog must be a string') if has('didLog') && $o<didLog> !~~ Str;
    bad('didWitness must be an array') if has('didWitness') && $o<didWitness> !~~ Positional;
    for <srcLog srcWitness> -> $k {
        next unless has($k);
        my $kind = reference-kind($o{$k}) // bad("$k is not a valid reference");
        bad("$k is local") if $remote && ($kind eq 'file' || $kind eq 'loopback');
    }
    my @selectors = <versionId versionTime versionNumber>.grep({ has($_) });
    bad('more than one version selector') if @selectors > 1;
    bad('versionId') if has('versionId') && $o<versionId> !~~ Str;
    bad('versionTime') if has('versionTime') && !valid-time($o<versionTime>);
    bad('versionNumber') if has('versionNumber') && !integer-at-least($o<versionNumber>, 1);
    bad('checkWatchers') if has('checkWatchers')
        && !(integer-at-least($o<checkWatchers>, 0) || ($o<checkWatchers> ~~ Str && $o<checkWatchers> eq 'all'));
    bad('extraWatchers') if has('extraWatchers') && !($o<extraWatchers> ~~ Positional
        && so $o<extraWatchers>.map({ printable($_) && $_ ~~ /^ 'https://' <-[/?#]> / }).all);
    bad('minCopies') if has('minCopies') && !integer-at-least($o<minCopies>, 1);
    bad('includeDidLog') if has('includeDidLog') && $o<includeDidLog> !~~ Bool;
    unsupported('retrieving srcLog is not supported') if has('srcLog');
    unsupported('checkWatchers') if has('checkWatchers') && !($o<checkWatchers> ~~ Numeric && $o<checkWatchers> == 0);
    unsupported('extraWatchers') if has('extraWatchers') && $o<extraWatchers>.elems;
    my $log = $o<didLog>;
    my @lines = log-lines($log);
    # The log needs witnessing if a witness list applies to an entry that passes the per-entry checks.
    my &needs-witnessing = { log-needs-witnessing($log, $now, :spec(didvh-spec($scid))) };
    unsupported('retrieving srcWitness is not supported') if has('srcWitness') && needs-witnessing();

    my %input = :$log, :$now, options => %(<versionId versionTime versionNumber minCopies>.grep({ has($_) }).map({ $_ => $o{$_} }));
    %input<witness> = $o<didWitness> if has('didWitness');
    my $r = resolve-log(%input, :spec(didvh-spec($scid)));
    my &vh-error = -> $e { fail-did(error-code($e<code>), $e<message>, $e) };
    vh-error($r<error>) unless $r<valid>;
    vh-error($r<error>) if !@selectors && $r<error>.defined && $r<error><code> eq 'unsupported-log-version';
    my $md = $r<metadata>;
    my $valid = $r<firstInvalidVersion>.defined ?? $r<firstInvalidVersion> - 1 !! @lines.elems;
    my @valid-lines = @lines[^$valid];
    my %document-metadata = <versionId versionTime created updated scid deactivated ttl watchers>.map({ $_ => $md{$_} });
    %document-metadata<witness> = $md<witness> if $md<witness>.defined;
    my %resolution-metadata = contentType => 'application/did+json';
    %resolution-metadata<warnings> = $md<warnings> if $md<warnings> && $md<warnings>.elems;
    if has('includeDidLog') && $o<includeDidLog> {
        %resolution-metadata<didLog> = @valid-lines.map({ "$_\n" }).join;
        %resolution-metadata<didWitness> = (has('didWitness') ?? $o<didWitness> !! []) if needs-witnessing();
    }
    %(didResolutionMetadata => %resolution-metadata,
      didDocument => ($md<deactivated> && !@selectors ?? Any !! $r<state>),
      didDocumentMetadata => %document-metadata)
}
# Offline resolution: {didResolutionMetadata, didDocument, didDocumentMetadata}.
sub resolve-did($did, $options, :$now, :$remote = False) is export {
    CATCH {
        when X::DidVh {
            my %details = title => .code, detail => .detail;
            %details<vhLog> = .vh-log if .vh-log.defined;
            return %(didResolutionMetadata => %(error => .code, problemDetails => %details),
                     didDocument => Any, didDocumentMetadata => %());
        }
    }
    resolve-or-die($did, $options, $now, $remote)
}

# ---------------------------------------------------------------- driver ops

sub didvh-dispatch(Str $op, $in) is export {
    given $op {
        when 'didvh-create' { create-did($in) }
        when 'didvh-update' { update-did($in) }
        when 'didvh-resolve' { resolve-did($in<did>, $in<options> // %(), now => $in<now>, remote => so ($in<remote> // False)) }
        when 'didvh-ref' {
            my $kind = reference-kind($in<ref>);
            $kind.defined ?? %(valid => True, :$kind) !! %(valid => False, error => 'invalidOptions')
        }
        when 'didvh-src' {
            my $l = src-locations($in<src>);
            $l.defined ?? %(valid => True, srcLog => $l[0], srcWitness => $l[1]) !! %(valid => False, error => 'invalidDidUrl')
        }
        when 'didvh-did-url' {
            my $u = parse-did-url($in<didUrl>);
            return %(valid => False, error => 'invalidDidUrl') unless $u.defined;
            my %r = valid => True, did => $u<did>, options => $u<options>;
            %r<fragment> = $u<fragment> if $u<fragment>.defined;
            %r
        }
        default { die 'unknown operation' }
    }
}
# Every protocol operation: VH-Log's and did:vh's.
sub perform(Str $op, $in) is export { $op.starts-with('didvh-') ?? didvh-dispatch($op, $in) !! dispatch($op, $in) }
