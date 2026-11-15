use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../local/lib/perl5";
use Test::More;
use VH::Log::JSON qw(decode_json decode_utf8 canonicalize format_number is_number is_string true false);

my $vectors = decode_json(do {
  open my $fh, '<:raw', "$FindBin::Bin/../../../vectors/primitives.json" or die $!;
  local $/;
  decode_utf8(<$fh>);
});
for my $case (@{ $vectors->{jcs} }) {
  is canonicalize(decode_json($case->{text})), $case->{output}, "jcs vector $case->{text}";
}

# Every JSON number is binary64, including integers beyond 2^53.
is canonicalize(decode_json('123456789012345678')), '123456789012345680', 'integers round to binary64';
is canonicalize(decode_json('[1.0,-0,1e21,1e-7,0.000001]')), '[1,0,1e+21,1e-7,0.000001]', 'ECMAScript thresholds';
is format_number(5e-324), '5e-324', 'smallest subnormal';
is format_number(1.7976931348623157e308), '1.7976931348623157e+308', 'largest double';
is format_number(2**-1022), '2.2250738585072014e-308', 'power-of-two boundary';
is format_number(9007199254740993), '9007199254740992', 'integer above 2^53';

# Strings and member names.
is canonicalize({ "\x{1F600}" => 1, "\x{FFFF}" => 2, "\r" => 3, a => 4 }),
  qq({"\\r":3,"a":4,"\x{1F600}":1,"\x{FFFF}":2}), 'member names sort by UTF-16 code units';
is canonicalize("\x00\x1f\"\\/\x{2028}"), qq("\\u0000\\u001f\\"\\\\/\x{2028}"), 'string escaping';
is canonicalize(decode_json('"\ud83d\ude00"')), qq("\x{1F600}"), 'surrogate pair escapes combine';
is canonicalize(decode_json('{"a\u0000x":1,"a":2}')), '{"a":2,"a\\u0000x":1}', 'NUL in member names';
is canonicalize(decode_json('{"d":1,"d":2}')), '{"d":2}', 'duplicate keys: last wins';

# Types follow the JSON::PP conventions.
ok is_number(decode_json('1')), 'parsed numbers are numbers';
ok is_string(decode_json('"1"')), 'parsed strings are strings';
is canonicalize([1, '1', true, false, undef, \1, \0]), '[1,"1",true,false,null,true,false]', 'Perl values';

# Rejections required by the profile and RFC 8259.
for my $bad ('1e400', '-1e400', '"\ud800"', '{"\udfff":1}', '"\ude00\ud83d"', '[1,]', '{"x":1} x',
  '01', '1.', '.5', '+1', 'NaN', "\"\x01\"", "'a'", '{a:1}', '[', '', ' ', 'tru') {
  ok !eval { decode_json($bad); 1 }, "rejects " . (length $bad ? $bad : 'empty text');
}
ok !eval { decode_utf8("\xed\xa0\x80"); 1 }, 'rejects UTF-8 surrogates';
ok !eval { decode_utf8("\xc0\xaf"); 1 }, 'rejects overlong UTF-8';
is decode_utf8("\xef\xbf\xbf"), "\x{FFFF}", 'accepts noncharacters';

done_testing;
