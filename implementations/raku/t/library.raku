use lib 'lib';
use Test;
use VHLog;
use VHLog::JSON;
use VHLog::Crypto;

is jcs(parse-json(Q|{"x":123456789012345678}|)), Q|{"x":123456789012345680}|,
    'numbers are rounded to binary64 at the parser boundary';
is jcs(parse-json('[295147905179352830000]')), '[295147905179352830000]',
    'shortest significant digits precede ECMAScript exponent formatting';
is jcs(parse-json(Q|{"x":"\u0061\u0301"}|)).encode('utf8-c8').list.join(','),
    '123,34,120,34,58,34,97,204,129,34,125', 'decomposed Unicode is preserved';
is jcs(parse-json(Q|{"\ufb33":1,"\ud83d\ude00":2}|)).encode('utf8-c8').decode('utf8-c8'),
    Buf.new(123,34,240,159,152,128,34,58,50,44,34,239,172,179,34,58,49,125).decode('utf8-c8'),
    'UTF-16 key ordering preserves presentation forms';
is jcs(parse-json('{"a":1,"a":2}')), '{"a":2}', 'last duplicate key wins';
dies-ok {parse-json('1e400')}, 'non-finite number rejected';
dies-ok {parse-json('"\ud800"')}, 'lone surrogate rejected';
dies-ok {parse-json(Buf.new(34,0xc0,0xaf,34).decode('utf8-c8'))}, 'overlong UTF-8 rejected';
is sha(Buf.new,512).list.map({sprintf('%02x',$_)}).join,
 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', 'SHA-512 native binding';
my $seed='00' x 32;
my $mk=multikey($seed);
my $proof=sign({value=>42},$seed);
ok verify({value=>42},$proof), 'Ed25519 proof verifies';
ok !verify({value=>43},$proof), 'changed document rejected';
my $first=create-log({state=>{id=>'example:{SCID}',value=>1},parameters=>{updateKeys=>[$mk]},versionTime=>'2026-01-01T00:00:00Z',signers=>[$seed]});
my $second=update-log({log=>$first<log>,state=>{value=>2},parameters=>{},versionTime=>'2026-01-01T00:00:01Z',signers=>[$seed]});
my $now='2026-01-02T00:00:00Z';
my $r=resolve-log({log=>$second<log>,:$now});
ok $r<valid>, 'create and update resolve';
is $r<metadata><versionNumber>,2,'latest version selected';
my $selected=resolve-log({log=>$second<log>,:$now,options=>{versionNumber=>1}});
is $selected<state><value>,1,'historical state selected';
my $partial=resolve-log({log=>$second<log>~"not JSON\n",:$now});
ok $partial<valid> && $partial<firstInvalidVersion>==3,'malformed suffix preserves valid prefix';
my $end=update-log({log=>$second<log>,state=>{value=>3},parameters=>{deactivated=>True},versionTime=>'2026-01-01T00:00:02Z',signers=>[$seed]});
my $deactivated=resolve-log({log=>$end<log>,:$now,options=>{versionNumber=>1}});
ok $deactivated<metadata><deactivated>, 'deactivation remains visible for historical selection';
my $copies=resolve-log({log=>$first<log>,:$now,copies=>[{source=>'watcher',log=>$second<log>},]});
is $copies<metadata><versionNumber>,2,'longest verified copy supplies state';
is $copies<metadata><copies>[0]<status>,'behind','older primary is reported behind';
is $copies<metadata><warnings>[0]<code>,'copy-behind','behind copy warning';
my @tampered = $second<log>.split("\n").grep(*.chars).map({parse-json($_)});
@tampered[0]<state><value> = 99;
my $extended-copy = resolve-log({
    log => $first<log>, :$now,
    copies => [{source => 'extension', log => @tampered.map({jcs($_)}).join("\n") ~ "\n"},],
});
ok $extended-copy<valid> && $extended-copy<metadata><versionNumber> == 2,
    'matching longer copy reuses verified prefix even when copy prefix content changed';
my $invalid-target = resolve-log({log => $second<log> ~ "invalid\n", :$now,
    options => {versionNumber => 3}});
is $invalid-target<error><code>, 'invalid-log', 'selecting malformed suffix returns its verification error';
is b58(Buf.new(0,0,1)), '112', 'base58 preserves leading zero bytes';
is un58('112').list.join(','), '0,0,1', 'base58 decoding preserves leading zero bytes';
done-testing;
