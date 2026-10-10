require json.fs
: alphabet ( -- addr len ) s" 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" ;
: base58 { bytes -- string }
  bytes j-size { n } n 2 * 1+ allocate throw { digits }
  digits n 2 * 1+ erase 0 { used } 0 { zeros }
  begin zeros n < if bytes j-data zeros + c@ 0= else false then while zeros 1+ to zeros repeat
  n zeros ?do
    bytes j-data i + c@ { carry }
    used 0 ?do digits i + c@ 256 * carry + 58 /mod to carry digits i + c! loop
    begin carry 0> while carry 58 /mod to carry digits used + c! used 1+ to used repeat
  loop
  empty$ { out } zeros 0 ?do out s" 1" str j-cat to out loop
  used 0 ?do out alphabet drop digits used 1- i - + c@ + c@ char$ j-cat to out loop
  digits free throw out ;
: unbase58 { text -- bytes|0 }
  text str? 0= if 0 exit then
  text j-size { n } n 1+ allocate throw { bytes } bytes n 1+ erase
  0 { used } 0 { zeros }
  begin zeros n < if text j-data zeros + c@ [char] 1 = else false then while zeros 1+ to zeros repeat
  n zeros ?do
    text j-data i + c@ { c } -1 { carry }
    58 0 ?do alphabet drop i + c@ c = if i to carry leave then loop
    carry 0< if bytes free throw 0 unloop exit then
    used 0 ?do bytes i + c@ 58 * carry + 256 /mod to carry bytes i + c! loop
    begin carry 0> while carry 256 /mod to carry bytes used + c! used 1+ to used repeat
  loop
  empty$ { out } zeros 0 ?do out 0 char$ j-cat to out loop
  used 0 ?do out bytes used 1- i - + c@ char$ j-cat to out loop
  bytes free throw out ;
: multihash ( string -- string ) j-sha 18 char$ 32 char$ j-cat swap j-cat base58 ;
: multikey ( seed -- string ) j-public dup 0= if -400 throw then
  237 char$ 1 char$ j-cat swap j-cat base58 s" z" str swap j-cat ;
: decode-key { key -- bytes|0 }
  key str? 0= if 0 exit then
  key 0 1 j-slice s" z" text= 0= if 0 exit then
  key 1 key j-size 1- j-slice unbase58 { bytes }
  bytes j-size 34 <> if 0 exit then
  bytes j-data c@ 237 <> bytes j-data 1+ c@ 1 <> or if 0 exit then
  bytes 2 32 j-slice ;
: hash? ( string -- flag ) unbase58 dup j-size 34 <> if drop false exit then
  j-data dup c@ 18 = swap 1+ c@ 32 = and ;
: verification-method ( multikey -- string ) dup s" did:key:" str swap j-cat s" #" str j-cat swap j-cat ;
: proof-key { proof -- key|0 }
  proof obj? 0= if 0 exit then
  proof s" verificationMethod" j-get { vm }
  vm str? 0= if 0 exit then
  vm 0 8 j-slice s" did:key:" text= 0= if 0 exit then
  vm s" #" str j-split { parts }
  parts j-size 2 <> if 0 exit then
  parts 1 j-at { key }
  key verification-method vm j-equal 0= if 0 exit then
  key decode-key 0= if 0 exit then key ;
: signing-input { document proof -- bytes }
  proof j-clone { config } config s" proofValue" j-del
  config jcs j-sha document without-proof jcs j-sha j-cat ;
: sign-proof { document seed vm created -- proof }
  j-object { proof }
  s" DataIntegrityProof" str proof s" type" put
  s" eddsa-jcs-2022" str proof s" cryptosuite" put
  s" assertionMethod" str proof s" proofPurpose" put
  vm 0= if seed multikey verification-method to vm then
  vm proof s" verificationMethod" put
  created if created proof s" created" put then
  document proof signing-input seed j-sign dup 0= if -400 throw then
  base58 s" z" str swap j-cat proof s" proofValue" put proof ;
: verify-proof { document proof -- flag }
  proof proof-key { key } key 0= if false exit then
  proof s" type" j-get s" DataIntegrityProof" text= 0= if false exit then
  proof s" cryptosuite" j-get s" eddsa-jcs-2022" text= 0= if false exit then
  proof s" proofPurpose" j-get s" assertionMethod" text= 0= if false exit then
  proof s" proofValue" j-get { sig }
  sig 0 1 j-slice s" z" text= 0= if false exit then
  sig 1 sig j-size 1- j-slice unbase58 to sig
  document proof signing-input sig key decode-key j-verify ;
: entry-hash { entry previous -- hash }
  entry without-proof { pre } previous pre s" versionId" put pre jcs multihash ;
: scid ( preliminary -- hash ) without-proof jcs multihash ;
