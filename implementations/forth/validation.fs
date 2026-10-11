require controller.fs
require time.fs
variable error-code
: demand { flag addr len -- } flag 0= if addr len str error-code ! -500 throw then ;
: parameter! ( flag -- ) s" invalid-parameter" demand ;
: structure! ( flag -- ) s" invalid-entry" demand ;
: defaults ( -- params )
  j-object { p }
  j-array p s" updateKeys" put j-array p s" nextKeyHashes" put
  j-array p s" watchers" put j-object p s" witness" put
  false j-bool p s" deactivated" put 3600 j-number p s" ttl" put p ;
: url? { url -- flag }
  url str? 0= if false exit then
  url j-size 0 ?do url j-data i + c@ 33 127 within 0= if false unloop exit then loop
  0 { start }
  url 0 8 j-slice s" https://" text= if 8 to start then
  url 0 7 j-slice s" http://" text= if 7 to start then
  start 0= url j-size start <= or if false exit then
  url j-data start + c@ dup [char] / <> swap dup [char] ? <> swap [char] # <> and and ;
: witness-config! { config -- }
  config obj? parameter! config j-size 0= if exit then
  config s" threshold" j-get { threshold } config s" witnesses" j-get { witnesses }
  threshold j-integral parameter! witnesses arr? parameter!
  threshold j-integer 1 witnesses j-size 1+ within parameter!
  j-array { ids }
  witnesses j-size 0 ?do
    witnesses i j-at s" id" j-get { id } id str? parameter! id j-size 0> parameter!
    id j-nfc to id
    id 0 8 j-slice s" did:key:" text= parameter!
    id 8 id j-size 8 - j-slice decode-key 0<> parameter!
    ids id contains? 0= parameter! ids id j-push
  loop ;
: array-values! { values xt -- }
  values arr? parameter! values j-size 0 ?do values i j-at xt execute parameter! loop ;
: multikey? ( key -- flag ) decode-key 0<> ;
: parameters! { p old first -- active }
  first p s" logVersion" j-has or if
    p s" logVersion" j-get s" vh-log:1.0" text= s" unsupported-log-version" demand
  then
  first if
    p s" scid" j-get str? parameter! p s" scid" j-get j-size 0> parameter!
    p s" updateKeys" j-has parameter!
  else p s" scid" j-has 0= parameter! then
  p s" updateKeys" j-has if p s" updateKeys" j-get ['] multikey? array-values! then
  p s" nextKeyHashes" j-has if p s" nextKeyHashes" j-get ['] hash? array-values! then
  p s" watchers" j-has if p s" watchers" j-get ['] url? array-values! then
  p s" witness" j-has if p s" witness" j-get witness-config! then
  p s" deactivated" j-has if p s" deactivated" j-get bool? parameter! then
  p s" ttl" j-has if
    p s" ttl" j-get { ttl } ttl j-integral parameter!
    ttl j-integer 0 2147483649 within parameter!
  then
  first 0= old s" nextKeyHashes" j-get j-size 0> and if
    p s" updateKeys" j-has p s" nextKeyHashes" j-has and s" prerotation-violation" demand
    p s" updateKeys" j-get { keys } keys j-size 0> s" prerotation-violation" demand
    keys j-size 0 ?do
      old s" nextKeyHashes" j-get keys i j-at multihash contains? s" prerotation-violation" demand
    loop
  then old p merge ;
: structure-check { entry -- }
  entry j-size 5 = structure!
  entry s" versionId" j-get str? structure!
  entry s" versionTime" j-get str? structure!
  entry s" parameters" j-get obj? structure!
  entry s" state" j-get obj? structure!
  entry s" proof" j-get arr? structure! ;
: proofs! { entry keys -- }
  entry s" proof" j-get { proofs }
  proofs j-size 0> s" invalid-proof" demand
  proofs j-size 0 ?do
    proofs i j-at { proof } proof proof-key { key }
    key 0<> s" invalid-proof" demand
    keys key contains? s" unauthorized-key" demand
    entry proof verify-proof s" invalid-proof" demand
  loop ;
: version-parts { id -- n hash }
  id s" -" str j-split { parts }
  parts j-size 2 <> if 0 0 exit then
  parts 0 j-at { number } number digits { n }
  n 1 < if 0 0 exit then
  number n integer$ j-equal 0= if 0 0 exit then
  n parts 1 j-at ;
: scid-check { entry -- }
  entry s" parameters" j-get s" scid" j-get { id }
  id hash? s" invalid-hash-algorithm" demand
  entry without-proof { pre } placeholder pre s" versionId" put
  pre j-dump id placeholder j-replace json-parse scid id j-equal s" scid-mismatch" demand ;
\ A scan is sequential. These variables form its transient validation context;
\ snapshots stored in the result are immutable copies of each accepted state.
variable scan-entry
variable scan-number
variable scan-active
variable scan-previous
variable scan-time
variable scan-now
variable scan-witness
: validate-entry ( -- )
  scan-entry @ { entry } scan-active @ { old } scan-number @ 1 = { first }
  entry obj? s" invalid-log" demand
  old s" deactivated" j-get j-truth 0= s" entry-after-deactivation" demand
  entry structure-check
  entry s" parameters" j-get old first parameters! { active }
  first old s" nextKeyHashes" j-get j-size 0> or if active else old then
  s" updateKeys" j-get entry swap proofs!
  entry s" versionId" j-get version-parts { n hash }
  n scan-number @ = s" invalid-version-id" demand
  hash j-size 0> hash unbase58 0<> and s" invalid-version-id" demand
  hash hash? s" invalid-hash-algorithm" demand
  first if active s" scid" j-get else scan-previous @ then { previous }
  entry previous entry-hash hash j-equal s" entry-hash-mismatch" demand
  entry s" versionTime" j-get timestamp { instant }
  instant 0>= s" invalid-version-time" demand
  first 0= if instant scan-time @ > s" invalid-version-time" demand then
  instant scan-now @ 300 + <= s" future-version-time" demand
  first if entry scid-check then
  old s" witness" j-get dup j-size 0= if drop active s" witness" j-get then scan-witness !
  active scan-active ! instant scan-time ! entry s" versionId" j-get scan-previous ! ;
: error-object { code version -- error }
  j-object { e } code e s" code" put code e s" message" put
  version if version j-number else 0 then e s" version" put e ;
: failure { error -- result }
  j-object { result } false j-bool result s" valid" put error result s" error" put result ;
: fail-code ( addr len -- result ) str 0 error-object failure ;
: entries-from-log { text -- entries }
  j-array { entries }
  text str? 0= if entries 0 j-push entries exit then
  text 10 char$ j-split { lines } lines j-size { n }
  \ Only the final LF is optional; blank interior lines are errors.
  n 1 > if lines n 1- j-at j-size 0= if n 1- to n then then
  n 0 ?do entries lines i j-at json-parse j-push loop entries ;
: scan-log { input -- scan }
  input s" log" j-get entries-from-log { entries }
  input s" now" j-get timestamp scan-now !
  defaults scan-active ! 0 scan-time ! 0 scan-previous !
  j-array { history } 0 { error }
  entries j-size 0 ?do
    entries i j-at scan-entry ! i 1+ scan-number !
    ['] validate-entry catch dup if
      dup -500 <> if throw then drop
      error-code @ i 1+ error-object to error leave
    then drop
    j-object { snapshot }
    scan-entry @ snapshot s" entry" put scan-active @ snapshot s" params" put
    scan-witness @ snapshot s" witness" put history snapshot j-push
  loop
  j-object { scan } entries scan s" entries" put history scan s" history" put
  input s" log" j-get j-size 0= if s" invalid-log" str 0 error-object to error then
  error scan s" error" put scan ;
