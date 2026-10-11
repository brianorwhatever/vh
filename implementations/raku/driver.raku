use lib 'lib';
use VHLog;
use VHLog::JSON;
$*IN.encoding('utf8-c8');
$*OUT.encoding('utf8-c8');
$*IN.nl-in = "\n";
for $*IN.lines -> $line {my $id;
    my $response;
    try {my $r=parse-json($line);
        $id=$r<id>;
        $response={:$id,ok=>True,result=>dispatch($r<op>,$r<input>)};
        CATCH {default {$response=%(:$id,ok=>False,error=>.message)}}};
    $*OUT.say(jcs($response));
    $*OUT.flush}
