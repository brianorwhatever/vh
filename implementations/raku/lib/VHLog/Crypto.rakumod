unit module VHLog::Crypto;
use NativeCall;
use VHLog::JSON;
sub sodium-lib { %*ENV<VHLOG_SODIUM> // ($*KERNEL.name eq 'darwin' ?? ('/opt/homebrew/lib/libsodium.dylib'.IO.e ?? '/opt/homebrew/lib/libsodium.dylib' !! '/usr/local/lib/libsodium.dylib') !! 'libsodium.so.23') }
sub crypto_hash_sha256(CArray[uint8], CArray[uint8], uint64 --> int32) is native(&sodium-lib) {*}
sub crypto_hash_sha512(CArray[uint8], CArray[uint8], uint64 --> int32) is native(&sodium-lib) {*}
sub crypto_sign_seed_keypair(CArray[uint8],CArray[uint8],CArray[uint8] --> int32) is native(&sodium-lib) {*}
sub crypto_sign_detached(CArray[uint8],CArray[uint64],CArray[uint8],uint64,CArray[uint8] --> int32) is native(&sodium-lib) {*}
sub crypto_sign_verify_detached(CArray[uint8],CArray[uint8],uint64,CArray[uint8] --> int32) is native(&sodium-lib) {*}
sub arr($bytes) { CArray[uint8].new(|$bytes.list) }
sub sha($bytes, $size=256) is export { my $out=CArray[uint8].new;
    $out[$size div 8 - 1]=0;
    ($size==256 ?? &crypto_hash_sha256 !! &crypto_hash_sha512)($out,arr($bytes),$bytes.elems);
    Buf.new((^($size div 8)).map({$out[$_]})) }
my $alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
sub b58($bytes) is export {my $n=0;
    for $bytes.list {$n=$n*256+$_};
    my $s='';
    while $n > 0 {$s=$alphabet.substr($n%58,1)~$s;
        $n div=58};
    my $z=0;
    for $bytes.list {last if $_!=0;
        $z++};
    '1' x $z ~ $s}
sub un58(Str $s) is export {die 'empty base58' unless $s.chars;
    my $n=0;
    for $s.comb {my $i=$alphabet.index($_);
        die 'base58' unless $i.defined;
        $n=$n*58+$i};
    my @b;
    while $n > 0 {@b.unshift($n%256);
        $n div=256};
    my $z=0;
    for $s.comb {last unless $_ eq '1';
        $z++};
    Buf.new(|(0 xx $z),|@b)}
sub hash-text(Str $s) is export {b58(Buf.new(0x12,0x20,|sha($s.encode('utf8-c8')).list))}
sub valid-hash($s) is export {return False unless $s ~~ Str;
    my $b=try un58($s);
    so $b.defined && $b.elems==34 && $b[0]==0x12 && $b[1]==0x20}
sub public-key(Str $mk) is export {die 'multikey' unless $mk.starts-with('z');
    my $b=un58($mk.substr(1));
    die 'multikey' unless $b.elems==34 && $b[0]==0xed && $b[1]==1;
    Buf.new($b[2..*])}
sub keypair(Str $seed) {die 'seed' unless $seed ~~ /^ <[0..9a..fA..F]> ** 64 $/;
    my $b=Buf.new($seed.comb(2).map({:16($_)}));
    my $pk=CArray[uint8].new;
    $pk[31]=0;
    my $sk=CArray[uint8].new;
    $sk[63]=0;
    crypto_sign_seed_keypair($pk,$sk,arr($b));
    ($pk,$sk)}
sub multikey(Str $seed) is export {my ($pk,$sk)=keypair($seed);
    'z'~b58(Buf.new(0xed,1,|(^32).map({$pk[$_]})))}
sub method-key($method) is export {return Nil unless $method ~~ Str;
    my $m=$method ~~ /^ 'did:key:' (<-[#]>+) '#' (<-[#]>+) $/;
    return Nil unless $m && ~$m[0] eq ~$m[1];
    ~$m[0]}
sub without-proof($d) is export {my %h=$d.Hash;
    %h<proof>:delete;
    %h}
sub sign($document,Str $seed, :$verificationMethod, :$created) is export {my $mk=multikey($seed);
    my %p=type=>'DataIntegrityProof',cryptosuite=>'eddsa-jcs-2022',verificationMethod=>($verificationMethod // "did:key:$mk#$mk"),proofPurpose=>'assertionMethod';
    %p<created> = $created if $created.defined;
    my $data=Buf.new(|sha(jcs(%p).encode('utf8-c8')).list,|sha(jcs(without-proof($document)).encode('utf8-c8')).list);
    my ($pk,$sk)=keypair($seed);
    my $sig=CArray[uint8].new;
    $sig[63]=0;
    my $len=CArray[uint64].new(0);
    crypto_sign_detached($sig,$len,arr($data),$data.elems,$sk);
    %p<proofValue>='z'~b58(Buf.new((^64).map({$sig[$_]})));
    %p}
sub verify($document,$proof) is export {my $ok=False;
    try {die 'proof' unless $proof ~~ Associative && $proof<type> eq 'DataIntegrityProof' && $proof<cryptosuite> eq 'eddsa-jcs-2022' && $proof<proofPurpose> eq 'assertionMethod';
        my $mk=method-key($proof<verificationMethod>);
        die 'method' unless $mk.defined;
        my $pk=public-key($mk);
        die 'signature' unless $proof<proofValue> ~~ Str && $proof<proofValue>.starts-with('z');
        my $sig=un58($proof<proofValue>.substr(1));
        die 'signature' unless $sig.elems==64;
        my %p=$proof.Hash;
        %p<proofValue>:delete;
        my $data=Buf.new(|sha(jcs(%p).encode('utf8-c8')).list,|sha(jcs(without-proof($document)).encode('utf8-c8')).list);
        $ok=crypto_sign_verify_detached(arr($sig),arr($data),$data.elems,arr($pk))==0};
    $ok}
