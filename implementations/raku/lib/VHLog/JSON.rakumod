unit module VHLog::JSON;
use NativeCall;
sub number-lib { $?FILE.IO.parent.parent.parent.add('native/libvhnumber.so').absolute }
sub vh_number(num64, CArray[uint8] --> int32) is native(&number-lib) {*}
# utf8-c8 retains the exact bytes even when NFG would otherwise normalize them.
sub cps(Str $s) is export {
    my @b = $s.encode('utf8-c8').list;
    my @u;
    my $i = 0;
    while $i < @b.elems {
        my $lead = @b[$i++];
        if $lead < 128 { @u.push($lead);
            next }
        die 'invalid UTF-8' unless 0xc2 <= $lead <= 0xf4;
        my $n = $lead < 224 ?? 1 !! $lead < 240 ?? 2 !! 3;
        die 'truncated UTF-8' if $i + $n > @b.elems;
        my $x = $lead +& ((1 +< (6-$n))-1);
        for ^$n {
            my $byte = @b[$i++];
            die 'invalid UTF-8 continuation' unless 128 <= $byte <= 191;
            $x = ($x +< 6) + ($byte +& 63);
        }
        die 'invalid UTF-8 scalar' if $x < (128,2048,65536)[$n-1]
        || 0xd800 <= $x <= 0xdfff || $x > 0x10ffff;
        @u.push($x);
    }
    @u
}
sub rawstr(@u --> Str) { my @b;
    for @u -> $c { if $c < 128 {@b.push($c)} elsif $c < 2048 {@b.append(0xc0 + ($c +> 6), 0x80 + ($c +& 63))} elsif $c < 65536 {@b.append(0xe0 + ($c +> 12), 0x80 + (($c +> 6) +& 63), 0x80 + ($c +& 63))} else {@b.append(0xf0 + ($c +> 18), 0x80 + (($c +> 12) +& 63), 0x80 + (($c +> 6) +& 63), 0x80 + ($c +& 63))} };
    Buf.new(@b).decode('utf8-c8') }
sub quote-json(Str $s) is export {
    my @out = 34;
    for cps($s) -> $c {
        my $escaped;
        given $c {
            when 34 { $escaped = '\\"' }
            when 92 { $escaped = '\\\\' }
            when 8  { $escaped = '\\b' }
            when 9  { $escaped = '\\t' }
            when 10 { $escaped = '\\n' }
            when 12 { $escaped = '\\f' }
            when 13 { $escaped = '\\r' }
            default { $escaped = sprintf('\\u%04x', $c) if $c < 32 }
        }
        $escaped.defined ?? @out.append($escaped.ords) !! @out.push($c);
    }
    @out.push(34);
    rawstr(@out)
}
sub number-json(Numeric $v) { my $b=CArray[uint8].new;
    $b[63]=0;
    die 'non-finite number' if vh_number($v.Num,$b) < 0;
    my $s=Buf.new((^64).map({$b[$_]})).decode.split("\0")[0];
    my ($mant,$ex)=$s.lc.split('e');
    my $neg=$mant.starts-with('-');
    $mant=$mant.substr(1) if $neg;
    my ($whole,$frac)=$mant.split('.');
    $frac //= '';
    my $digits=$whole~$frac;
    my $pos=$whole.chars+($ex // 0).Int;
    while $digits.starts-with('0') && $digits.chars > 1 {$digits=$digits.substr(1);
        $pos--};
    while $digits.ends-with('0') && $digits.chars > 1 {$digits=$digits.substr(0,*-1)};
    my $out;
    if $pos > 0 && $pos <=21 {$out=$pos >=$digits.chars ?? $digits~('0' x ($pos-$digits.chars)) !! $digits.substr(0,$pos)~'.'~$digits.substr($pos)} elsif $pos <= 0 && $pos> -6 {$out='0.'~('0' x -$pos)~$digits} else {my $e=$pos-1;
        $out=$digits.substr(0,1)~($digits.chars > 1 ?? '.'~$digits.substr(1) !! '')~'e'~($e >= 0 ?? '+' !! '')~$e};
    ($neg ?? '-' !! '')~$out }
sub key-order(Str $s) { cps($s).map({$_ > 0xffff ?? (0xd800+(($_-0x10000)+>10),0xdc00+(($_-0x10000)+&1023)) !! $_}).flat.map({sprintf('%04x',$_)}).join }
sub jcs($v) is export { return 'null' unless $v.defined;
    given $v {when Bool {$_ ?? 'true' !! 'false'};
        when Str {quote-json($_)};
        when Numeric {number-json($_)};
        when Associative {'{'~.keys.sort({key-order($^a) cmp key-order($^b)}).map({quote-json($_)~':'~jcs($v{$_})}).join(',')~'}'};
        when Positional {'['~.map({jcs($_)}).join(',')~']'};
        default {die 'unsupported JSON value'}} }
class Parser {
    has @.u;
    has Int $.i is rw=0;
    method ws { $!i++ while $!i < @!u.elems && @!u[$!i] == any(9,10,13,32) }
    method take($c) {self.ws;
        die 'JSON syntax' unless @!u[$!i++] == $c}
    method str {self.take(34);
        my @v;
        loop {die 'unterminated string' if $!i >= @!u.elems;
            my $c=@!u[$!i++];
            last if $c==34;
            die 'control character' if $c < 32;
            if $c==92 {my $e=@!u[$!i++];
                if $e==117 {my $h=self.hex;
                    if 0xd800 <=$h <= 0xdbff {die 'lone surrogate' unless @!u[$!i++]==92 && @!u[$!i++]==117;
                        my $l=self.hex;
                        die 'lone surrogate' unless 0xdc00 <=$l <= 0xdfff;
                        $h=0x10000+(($h-0xd800)+<10)+$l-0xdc00} elsif 0xdc00 <=$h <= 0xdfff {die 'lone surrogate'};
                    @v.push($h)} else {my %esc=34=>34,92=>92,47=>47,98=>8,102=>12,110=>10,114=>13,116=>9;
                    die 'bad escape' unless %esc{$e}:exists;
                    @v.push(%esc{$e})}}else{@v.push($c)}};
        rawstr(@v) }
    method hex {my $s=rawstr(@!u[$!i..$!i+3]);
        $!i+=4;
        die 'bad escape' unless $s ~~ /^ <[0..9a..fA..F]> ** 4 $/;
        :16($s)}
    method value {self.ws;
        my $c=@!u[$!i];
        return self.str if $c==34;
        if $c==123 {$!i++;
            my %h;
            self.ws;
            if @!u[$!i]==125 {$!i++;
                return %h};
            loop {my $k=self.str;
                self.take(58);
                %h{$k}=self.value;
                self.ws;
                last if @!u[$!i++]==125;
                die 'bad object' unless @!u[$!i-1]==44};
            return %h};
        if $c==91 {$!i++;
            my @a;
            self.ws;
            if @!u[$!i]==93 {$!i++;
                return @a.Array};
            loop {@a.push(self.value);
                self.ws;
                last if @!u[$!i++]==93;
                die 'bad array' unless @!u[$!i-1]==44};
            return @a.Array};
        for ('true',True),('false',False),('null',Any) -> $p {if $!i+$p[0].chars <= @!u.elems && rawstr(@!u[$!i..^($!i+$p[0].chars)]) eq $p[0] {$!i+=$p[0].chars;
                return $p[1]}};
        my $s=rawstr(@!u[$!i..*]);
        my $m=$s ~~ /^ '-'? [0 | <[1..9]> <[0..9]>*] ['.' <[0..9]>+]? [<[eE]> <[+\-]>? <[0..9]>+]? /;
        die 'JSON value' unless $m;
        $!i+=$m.Str.chars;
        my $n=$m.Str.Num;
        die 'non-finite number' unless $n.abs < Inf;
        $n }
}
sub parse-json(Str $s) is export { my $p=Parser.new(u=>cps($s));
    my $v=$p.value;
    $p.ws;
    die 'trailing JSON' unless $p.i==$p.u.elems;
    $v }
