unit module VHLog;
use VHLog::JSON;
use VHLog::Crypto;

# Exclude proofs and substitute the predecessor before hashing.
sub entry-hash($entry,$previous) is export { my %e=without-proof($entry);
    %e<versionId>=$previous;
    hash-text(jcs(%e)) }
sub scid($entry) is export {hash-text(jcs(without-proof($entry)))}
# Published entry fields follow the controller profile order; nested data uses JCS.
sub entry-line($entry) {
    '{' ~ <versionId versionTime parameters state proof>.map({
        quote-json($_) ~ ':' ~ jcs($entry{$_})
    }).join(',') ~ '}'
}

sub create-log($input) is export {my %p=$input<parameters>.Hash;
    %p<scid>//='{SCID}';
    %p<logVersion>//='vh-log:1.0';
    my %e=versionId=>'{SCID}',versionTime=>$input<versionTime>,parameters=>%p,state=>$input<state>;
    my $scid=scid(%e);
    %e=parse-json(jcs(%e).subst('{SCID}',$scid,:g));
    %e<versionId>='1-'~entry-hash(%e,$scid);
    %e<proof>=$input<signers>.map({sign(%e,$_,created=>$input<versionTime>)}).Array;
    {log=>entry-line(%e)~"\n",:$scid,versionId=>%e<versionId>}}
sub read-log(Str $log) {my @lines=$log.split("\n");
    @lines.pop while @lines && @lines[*-1].trim eq '';
    die 'invalid-log' unless @lines;
    my @entries;
    for @lines {my $e=parse-json($_);
        die 'invalid-log' unless $e ~~ Associative;
        @entries.push($e)};
    @entries}
sub update-log($input) is export {my @e=read-log($input<log>);
    my $prev=@e[*-1]<versionId>;
    my $n=$prev.split('-')[0].Int+1;
    my %e=versionId=>$prev,versionTime=>$input<versionTime>,parameters=>($input<parameters>//{}),state=>$input<state>;
    %e<versionId>="$n-"~entry-hash(%e,$prev);
    %e<proof>=$input<signers>.map({sign(%e,$_,created=>$input<versionTime>)}).Array;
    {log=>$input<log>.trim-trailing~"\n"~entry-line(%e)~"\n",versionId=>%e<versionId>}}

# Proleptic Gregorian arithmetic supports every four-digit year, including 0000.
sub instant($s) {return Nil unless $s ~~ Str;
    my $m=$s ~~ /^ (\d ** 4) '-' (\d ** 2) '-' (\d ** 2) 'T' (\d ** 2) ':' (\d ** 2) ':' (\d ** 2) ['Z'|'+00:00'] $/;
    return Nil unless $m;
    my ($y,$mo,$d,$h,$mi,$se)=$m.list.map(*.Int);
    return Nil unless 1 <= $mo <= 12 && 0 <= $h <= 23 && 0 <= $mi <= 59 && 0 <= $se <= 59;
    my $leap=$y%4==0 && ($y%100!=0 || $y%400==0);
    my @days=31,($leap ?? 29 !! 28),31,30,31,30,31,31,30,31,30,31;
    return Nil unless 1 <= $d <= @days[$mo-1];
    my $days=365*$y+ (($y+3) div 4)-(($y+99) div 100)+(($y+399) div 400);
    $days+=@days[^($mo-1)].sum+$d-1;
    ($days*24+$h)*3600+$mi*60+$se}
sub is-uint($v,$max=Inf) {so $v ~~ Numeric && $v !~~ Bool && $v >= 0 && $v <= $max && $v == $v.floor}
sub err($code,$version?) {my %e=:$code,message=>$code,:$version;
    %e}
sub failure($code,$version?) { {valid=>False,error=>err($code,$version)} }
sub defaults { {nextKeyHashes=>[],witness=>{},watchers=>[],deactivated=>False,ttl=>3600} }

# Validate parameters before proofs, including explicit pre-rotation commitments.
sub parameter-error($p,$prior,$n) {
    for $p.keys -> $k {my $v=$p{$k};
        return 'invalid-parameter' unless $v.defined;
        given $k {
            when 'logVersion' {return 'invalid-parameter' unless $v ~~ Str;
                return 'unsupported-log-version' unless $v eq 'vh-log:1.0'}
            when 'scid' {return 'invalid-parameter' unless $n==1 && $v ~~ Str}
            when 'updateKeys'|'nextKeyHashes' {return 'invalid-parameter' unless $v ~~ Positional && $v.all ~~ Str;
                for $v.list {if $k eq 'updateKeys' {return 'invalid-parameter' unless (try public-key($_)).defined} else {return 'invalid-parameter' unless valid-hash($_)}}}
            when 'ttl' {return 'invalid-parameter' unless is-uint($v,2**31)}
            when 'deactivated' {return 'invalid-parameter' unless $v ~~ Bool}
            when 'watchers' {return 'invalid-parameter' unless $v ~~ Positional;
                for $v.list {return 'invalid-parameter' unless $_ ~~ Str && $_ ~~ /^ 'http' 's'? '://' <-[/\?#]>+ / && cps($_).all >=33 && cps($_).all <=126}}
            when 'witness' {return 'invalid-parameter' unless $v ~~ Associative;
                if $v.elems {return 'invalid-parameter' unless $v.keys.sort.join(',') eq 'threshold,witnesses' && is-uint($v<threshold>) && $v<threshold> > 0 && $v<witnesses> ~~ Positional && $v<witnesses>.elems >= $v<threshold>;
                    my %ids;
                    for $v<witnesses>.list -> $w {return 'invalid-parameter' unless $w ~~ Associative && $w.keys.elems==1 && $w<id> ~~ Str && $w<id>.starts-with('did:key:') && (try public-key($w<id>.substr(8))).defined;
                        my $id=$w<id>.NFC.Str;
                        return 'invalid-parameter' if %ids{$id}:exists;
                        %ids{$id}=True}}}
        }}
    if $n==1 {return 'unsupported-log-version' unless $p<logVersion>:exists;
        return 'invalid-parameter' unless ($p<scid>:exists) && ($p<updateKeys>:exists)}
    if $n > 1 && $prior<nextKeyHashes>.elems {return 'prerotation-violation' unless ($p<updateKeys>:exists) && ($p<nextKeyHashes>:exists) && $p<updateKeys>.elems;
        for $p<updateKeys>.list {return 'prerotation-violation' unless hash-text($_) eq any($prior<nextKeyHashes>.list)}}
    Nil
}

# Verify a copy in profile check order, retaining snapshots of its valid prefix.
sub inspect($input) {
    my @entries;
    my $parse-error;
    my $parse-first;
    my @lines=$input<log>.split("\n");
    @lines.pop while @lines && @lines[*-1].trim eq '';
    return {entries=>[],configs=>[],error=>err('invalid-log'),first=>1} unless @lines;
    for @lines.kv -> $i,$line {my $e;
        my $ok=True;
        try {$e=parse-json($line);
            die 'object required' unless $e ~~ Associative;
            CATCH {default {$ok=False}}};
        unless $ok {$parse-first=$i+1;
            $parse-error=err('invalid-log',$parse-first);
            last};
        @entries.push($e)}
    my %active=defaults;
    my @configs;
    my @witnesses;
    my $error;
    my $first;
    my $lasttime;
    my $now=instant($input<now>);
    for @entries.kv -> $i,$e {my $n=$i+1;
        my $code;
        if %active<deactivated> {$code='entry-after-deactivation'} elsif $e.keys.sort.join(',') ne 'parameters,proof,state,versionId,versionTime' || $e<versionId> !~~ Str || $e<versionTime> !~~ Str || $e<parameters> !~~ Associative || $e<state> !~~ Associative || $e<proof> !~~ Positional {$code='invalid-entry'} else {
            my $p=$e<parameters>;
            $code=parameter-error($p,%active,$n);
            unless $code.defined {my %next=%active;
                for $p.kv -> $k,$v {%next{$k}=$v};
                # Ordinary rotations are authorized by prior keys; pre-rotation uses current keys.
                my $keys=$n==1 || %active<nextKeyHashes>.elems ?? %next<updateKeys> !! %active<updateKeys>;
                # Replacing an active witness list takes effect only after this entry.
                my $wc=%active<witness>.elems ?? %active<witness> !! %next<witness>;
                if !$e<proof>.elems {$code='invalid-proof'} else {for $e<proof>.list -> $pr {my $mk=$pr ~~ Associative ?? method-key($pr<verificationMethod>) !! Nil;
                        if !$mk.defined {$code='invalid-proof';
                            last};
                        unless $mk eq any($keys.list) {$code='unauthorized-key';
                            last};
                        unless verify($e,$pr) {$code='invalid-proof';
                            last}}}
                unless $code.defined {my $m=$e<versionId> ~~ /^ (<[1..9]> \d*) '-' (<-[\-]>+) $/;
                    if !$m || $m[0].Int!=$n {$code='invalid-version-id'} elsif !(try un58(~$m[1])).defined {$code='invalid-version-id'} elsif !valid-hash(~$m[1]) {$code='invalid-hash-algorithm'} elsif entry-hash($e,$i==0 ?? %next<scid> !! @entries[$i-1]<versionId>) ne ~$m[1] {$code='entry-hash-mismatch'}}
                unless $code.defined {my $t=instant($e<versionTime>);
                    if !$t.defined || ($lasttime.defined && $t <= $lasttime) {$code='invalid-version-time'} elsif $now.defined && $t > $now+300 {$code='future-version-time'} else {$lasttime=$t}}
                unless $code.defined {if $n==1 {my $sc=%next<scid>;
                        if !valid-hash($sc) {$code='invalid-hash-algorithm'} else {my %pre=without-proof($e);
                            %pre<versionId>='{SCID}';
                            my $re=parse-json(jcs(%pre).subst($sc,'{SCID}',:g));
                            $code='scid-mismatch' if scid($re) ne $sc}}}
                unless $code.defined {%active=%next;
                    @configs.push(%active.Hash.clone);
                    @witnesses.push($wc)}
            }
        };
        if $code.defined {$error=err($code,$n);
            $first=$n;
            last}}
    # Witness checks run after the structural, cryptographic and timestamp checks.
    unless $error.defined {if @witnesses.grep(*.elems).elems {my $wf=$input<witness>//[];
            my $malformed=($input<witness>:exists) && (!$input<witness>.defined || $wf !~~ Positional);
            unless $malformed {for $wf.list -> $r {if $r !~~ Associative || $r.keys.sort.join(',') ne 'proof,versionId' || $r<versionId> !~~ Str || $r<proof> !~~ Positional {$malformed=True;
                        last}}};
            for @witnesses.kv -> $i,$wc {next unless $wc.elems;
                next if $i < ($input<trustedEntries>//0);
                my %approved;
                unless $malformed {for $wf.list -> $row {my $idx=@entries.first({$_<versionId> eq $row<versionId>},:k);
                        next unless $idx.defined && $idx >= $i;
                        for $row<proof>.list -> $pr {my $mk=$pr ~~ Associative ?? method-key($pr<verificationMethod>) !! Nil;
                            next unless $mk.defined;
                            my $id='did:key:'~$mk;
                            next unless $wc<witnesses>.first({$_<id>.NFC.Str eq $id}).defined;
                            if verify({versionId=>$row<versionId>},$pr) {%approved{$id}=True}}}};
                if $malformed || %approved.elems < $wc<threshold> {$first=$i+1;
                    $error=err($malformed ?? 'invalid-witness-file' !! 'witness-threshold-not-met',$first);
                    last}}}}
    unless $error.defined {$error=$parse-error;
        $first=$parse-first};
    {entries=>@entries.Array,configs=>@configs.Array,:$error,:$first,count=>@lines.elems}
}

# Select a historical state while reporting the latest valid log metadata.
sub render($input,$checked,@extra-warnings=(),$copies?) {
    my @e=$checked<entries>.list;
    my @configs=$checked<configs>.list;
    my $error=$checked<error>;
    my $first=$checked<first>;
    my $validcount=$first.defined ?? $first-1 !! @e.elems;
    return {valid=>False,:$error} if $validcount==0;
    my $o=$input<options>//{};
    my $idx=$validcount-1;
    if $o<versionNumber>:exists {$idx=$o<versionNumber>.Int-1;
        return {valid=>False,:$error} if $error.defined && $idx >= $validcount && $idx < ($checked<count>//@e.elems);
        return failure('not-found') if $idx >= @e.elems}
    elsif $o<versionId>:exists {my $found=@e.first({$_<versionId> eq $o<versionId>},:k);
        return failure('not-found') unless $found.defined;
        $idx=$found}
    elsif $o<versionTime>:exists {my $t=instant($o<versionTime>);
        my @found=(^@e.elems).grep({my $et=instant(@e[$_]<versionTime>);
            $et.defined && $et <= $t});
        return failure('not-found') unless @found;
        $idx=@found[*-1]}
    return {valid=>False,:$error} if $idx >= $validcount;
    my $e=@e[$idx];
    my $p=@configs[$idx];
    my $lastp=@configs[$validcount-1];
    my @warnings=@extra-warnings;
    @warnings.push({code=>'invalid-entries',message=>'invalid entries'}) if $error.defined;
    my %metadata=versionId=>$e<versionId>,versionTime=>$e<versionTime>,versionNumber=>$idx+1,created=>@e[0]<versionTime>,updated=>@e[$validcount-1]<versionTime>,scid=>@configs[0]<scid>,deactivated=>$lastp<deactivated>,ttl=>$lastp<ttl>,witness=>($lastp<witness>.elems ?? $lastp<witness> !! Any),watchers=>$lastp<watchers>,updateKeys=>$p<updateKeys>,nextKeyHashes=>$p<nextKeyHashes>,warnings=>@warnings.Array;
    %metadata<copies>=$copies if $copies.defined;
    {valid=>True,state=>$e<state>,metadata=>%metadata,firstInvalidVersion=>$first,error=>$error}
}

# Prefer a fully verified primary; compare copies by their overlapping versionId.
sub resolve-log($input) is export {
    my $o=$input<options>//{};
    return failure('invalid-option') unless $o ~~ Associative;
    return failure('invalid-option') if $o.keys.grep({$_ ne any(<versionId versionTime versionNumber minCopies>)}).elems || $o.keys.grep({$_ eq any(<versionId versionTime versionNumber>)}).elems > 1;
    return failure('invalid-option') if ($o<versionNumber>:exists) && (!is-uint($o<versionNumber>) || $o<versionNumber> < 1);
    return failure('invalid-option') if ($o<minCopies>:exists) && (!is-uint($o<minCopies>) || $o<minCopies> < 1);
    return failure('invalid-option') if ($o<versionId>:exists) && $o<versionId> !~~ Str;
    return failure('invalid-option') if ($o<versionTime>:exists) && !instant($o<versionTime>).defined;
    my $primary=inspect($input);
    return render($input,$primary) unless ($input<copies>:exists) || ($input<retainedVersionId>:exists) || ($o<minCopies>//1) > 1;
    my @all;
    @all.push({source=>'primary',log=>$input<log>,witness=>$input<witness>,hasWitness=>($input<witness>:exists)});
    @all.append($input<copies>.list) if $input<copies> ~~ Positional;
    my @checks;
    my $ref;
    my $refi;
    for @all.kv -> $i,$copy {if $copy<unavailable>:exists {@checks.push(Nil);
            next};
        my %in=log=>$copy<log>,now=>$input<now>;
        %in<witness>=$copy<witness> if ($copy<witness>:exists) && ($i!=0 || $copy<hasWitness>);
        my $c=$i==0 ?? $primary !! inspect(%in);
        @checks.push($c);
        if !$c<error>.defined && !$ref.defined {$ref=$c;
            $refi=$i}}
    unless $ref.defined {return failure('min-copies-not-met') if ($o<minCopies>//1)>1;
        return render($input,$primary)}
    for @all.kv -> $i,$copy {next if $i==$refi || !@checks[$i].defined;
        my $c=@checks[$i];
        my $len=$c<entries>.elems;
        my $rl=$ref<entries>.elems;
        next unless $len;
        my $k=($len min $rl)-1;
        if $c<entries>[$k]<versionId> eq $ref<entries>[$k]<versionId> {if $len > $rl {
                # Reuse the verified reference prefix; only the additional copy entries matter.
                my %extended=log=>($ref<entries>.list.map({jcs($_)}).join("\n")~"\n"~$c<entries>[$rl..*].map({jcs($_)}).join("\n")~"\n"),now=>$input<now>,trustedEntries=>$rl;
                %extended<witness>=$copy<witness> if $copy<witness>:exists;
                my $extended=inspect(%extended);
                @checks[$i]=$extended;
                if !$extended<error>.defined {$ref=$extended;
                    $refi=$i}
            }} elsif !$c<error>.defined {my $fork=(^($len min $rl)).first({$c<entries>[$_]<versionId> ne $ref<entries>[$_]<versionId>});
            my %er=err('fork-detected',$fork+1);
            %er<fork>={version=>$fork+1,copies=>[{source=>@all[$refi]<source>,versionId=>$ref<entries>[$fork]<versionId>},{source=>$copy<source>,versionId=>$c<entries>[$fork]<versionId>}]};
            return {valid=>False,error=>%er}}}
    my @warnings;
    my @statuses;
    for @all.kv -> $i,$copy {my %status=source=>$copy<source>;
        my $c=@checks[$i];
        if !$c.defined {%status<status>='unavailable';
            @warnings.push({code=>'copy-unavailable',source=>$copy<source>,message=>'copy unavailable'})} else {my $len=$c<entries>.elems;
            my $rl=$ref<entries>.elems;
            my $match=($i != 0 || !$c<error>.defined) && $len > 0 && $len <= $rl && $c<entries>[$len-1]<versionId> eq $ref<entries>[$len-1]<versionId>;
            %status<status>=$match ?? ($len==$rl ?? 'current' !! 'behind') !! 'invalid';
            %status<versionId>=$c<entries>[$len-1]<versionId> if $len;
            @warnings.push({code=>'copy-invalid',source=>$copy<source>,message=>'invalid copy'}) unless $match};
        @warnings.push({code=>'copy-behind',source=>$copy<source>,message=>'copy behind'}) if %status<status> eq 'behind';
        @statuses.push(%status)}
    if $input<retainedVersionId>:exists {my $v=$input<retainedVersionId>;
        my $n=try $v.split('-')[0].Int;
        if !$n.defined || $n < 1 || $n > $ref<entries>.elems {@warnings.push({code=>'retained-version-not-found',message=>'retained version unavailable'})} elsif $ref<entries>[$n-1]<versionId> ne $v {my %er=err('fork-detected',$n);
            %er<fork>={version=>$n,copies=>[{source=>@all[$refi]<source>,versionId=>$ref<entries>[$n-1]<versionId>},{source=>'retained',versionId=>$v}]};
            return {valid=>False,error=>%er}}}
    return failure('min-copies-not-met') if @statuses.grep({$_<status> eq any('current','behind')}).elems < ($o<minCopies>//1);
    render($input,$ref,@warnings,@statuses.Array)
}
sub dispatch(Str $op,$in) is export {given $op {when 'jcs' {{output=>jcs(parse-json($in<text>))}};
        when 'hash'|'key-hash' {{output=>hash-text($in<data>//$in<multikey>)}};
        when 'multikey' {{multikey=>multikey($in<seed>)}};
        when 'scid' {{scid=>scid($in<entry>)}};
        when 'entry-hash' {{hash=>entry-hash($in<entry>,$in<previousVersionId>)}};
        when 'sign' {{proof=>sign($in<document>,$in<seed>,verificationMethod=>$in<verificationMethod>,created=>$in<created>)}};
        when 'verify' {{valid=>verify($in<document>,$in<proof>)}};
        when 'create' {create-log($in)};
        when 'update' {update-log($in)};
        when 'witness' {{proof=>sign({versionId=>$in<versionId>},$in<seed>,created=>$in<created>)}};
        when 'resolve' {resolve-log($in)};
        default {die 'unknown operation'}}}
