\ did:vh (docs/didvh-profile.md) on top of the VH-Log words: DIDs, create and
\ update, srcLog/srcWitness references, the src DID URL parameter, DID URLs,
\ and offline resolution. Strings are byte strings holding UTF-8.
require resolver.fs

\ ------------------------------------------------------------ byte helpers

: byte@ ( string i -- c ) swap j-data + c@ ;
: from { s i -- string } s i s j-size i - j-slice ;
: upto { s i -- string } s 0 i j-slice ;
: index-of { s c -- i|-1 }
  s j-size 0 ?do s j-data i + c@ c = if i unloop exit then loop -1 ;
: in-set? { c addr len -- flag }
  len 0 ?do addr i + c@ c = if true unloop exit then loop false ;
: index-of-any { s addr len -- i|-1 }
  s j-size 0 ?do s j-data i + c@ addr len in-set? if i unloop exit then loop -1 ;
: starts? { s addr len -- flag } s 0 len j-slice addr len text= 0<> ;
: ascii-digit? ( c -- flag ) [char] 0 [char] 9 1+ within ;
: alpha? ( c -- flag ) 32 or [char] a [char] z 1+ within ;
: all-digits? { s -- flag }
  s j-size 0= if false exit then
  s j-size 0 ?do s i byte@ ascii-digit? 0= if false unloop exit then loop true ;
\ A non-negative decimal integer with no leading zeros.
: decimal? { s -- flag }
  s all-digits? 0= if false exit then s j-size 1 = s 0 byte@ [char] 0 <> or ;
: printable? { s -- flag }
  s j-size 0 ?do s i byte@ 33 127 within 0= if false unloop exit then loop true ;
: lower { s -- string }
  empty$ { out }
  s j-size 0 ?do
    s i byte@ dup [char] A [char] Z 1+ within if 32 + then char$ out swap j-cat to out
  loop out ;
: segments ( path -- array ) 1 from s" /" str j-split ;

\ ------------------------------------------------------------ UTF-8

: continuation? ( c -- flag ) 192 and 128 = ;
\ The code point at byte AT and its length, or 0 0 if it is not well-formed.
: utf8-at { s at -- cp n }
  0 0 0 { b n cp }
  s at byte@ to b
  b 128 < if b 1 exit then
  b 194 224 within if 2 to n b 31 and to cp else
  b 224 240 within if 3 to n b 15 and to cp else
  b 240 245 within if 4 to n b 7 and to cp else 0 0 exit then then then
  at n + s j-size > if 0 0 exit then
  n 1 ?do
    s at i + byte@ dup continuation? 0= if drop 0 0 unloop exit then
    63 and cp 6 lshift or to cp
  loop
  n 3 = cp 2048 < and n 4 = cp 65536 < and or if 0 0 exit then
  cp 55296 57344 within cp 1114111 > or if 0 0 exit then
  cp n ;
: utf8? { s -- flag }
  0 { at }
  begin at s j-size < while
    s at utf8-at nip dup 0= if drop false exit then at + to at
  repeat true ;
: last-code-point { s -- cp }
  s j-size 1- { at }
  begin at 0> s at byte@ continuation? and while at 1- to at repeat
  s at utf8-at drop ;
\ Unicode White_Space.
: white-space? { cp -- flag }
  cp 9 14 within cp 32 = or cp 133 = or cp 160 = or cp 5760 = or
  cp 8192 8203 within or cp 8232 = or cp 8233 = or cp 8239 = or
  cp 8287 = or cp 12288 = or ;

: hex-digit ( c -- n|-1 )
  dup ascii-digit? if [char] 0 - exit then
  32 or dup [char] a [char] f 1+ within if [char] a - 10 + else drop -1 then ;
\ Percent-decodes once as UTF-8; "+" stays "+" and an unescaped character is
\ kept as it is. 0 for a malformed escape or invalid UTF-8.
: percent-decode { s -- string|0 }
  empty$ 0 0 0 { out at hi lo }
  begin at s j-size < while
    s at byte@ [char] % = if
      at 3 + s j-size > if 0 exit then
      s at 1+ byte@ hex-digit to hi s at 2 + byte@ hex-digit to lo
      hi 0< lo 0< or if 0 exit then
      out hi 16 * lo + char$ j-cat to out at 3 + to at
    else
      out s at byte@ char$ j-cat to out at 1+ to at
    then
  repeat out utf8? if out else 0 then ;

\ ------------------------------------------------------------ the DID (section 2)

: base58-char? ( c -- flag ) alphabet in-set? ;
\ The SCID of a did:vh DID ("did:vh:" and 46 base58btc characters), or 0.
: did-scid-of { did -- scid|0 }
  did str? 0= if 0 exit then
  did j-size 53 <> if 0 exit then
  did s" did:vh:" starts? 0= if 0 exit then
  did 7 from { scid }
  46 0 ?do scid i byte@ base58-char? 0= if 0 unloop exit then loop scid ;
\ did:vh:<major>.<minor>
: method? { v -- flag }
  v s" did:vh:" starts? 0= if false exit then
  v 7 from s" ." str j-split { parts }
  parts j-size 2 <> if false exit then
  parts 0 j-at decimal? parts 1 j-at decimal? and ;
variable did-scid  \ the DID's SCID while resolving, or 0
: did-state? { state scid -- flag }
  did-scid @ if did-scid @ scid j-equal 0= if false exit then then
  state s" id" j-get s" did:vh:" str scid j-cat j-equal 0<> ;
: did-specialisation ( -- )
  s" method" spec-parameter 2! s" did:vh:1.0" spec-version 2!
  ['] method? spec-syntax ! true spec-closed ! ['] did-state? spec-state ! ;

\ ------------------------------------------------------------ create / update

: with-state ( input -- input ) j-clone dup s" document" j-get swap dup >r s" state" put r> ;
: didvh-create ( input -- result )
  with-state did-specialisation ['] create-log catch vh-log-specialisation throw
  { result } s" did:vh:" str result s" scid" j-get j-cat result s" did" put result ;
: didvh-update ( input -- result ) with-state update-log ;

\ ------------------------------------------------------------ references (section 3)

\ The index of the ":" after a scheme [A-Za-z][A-Za-z0-9+.-]*, or -1.
: scheme-end { s -- i|-1 }
  s [char] : index-of { colon }
  colon 1 < if -1 exit then
  s 0 byte@ alpha? 0= if -1 exit then
  colon 0 ?do
    s i byte@ dup alpha? over ascii-digit? or swap s" +.-" in-set? or 0= if -1 unloop exit then
  loop colon ;
: label? { l -- flag }
  l j-size 1 64 within 0= if false exit then
  l j-size 0 ?do
    l i byte@ dup [char] a [char] z 1+ within over ascii-digit? or swap [char] - = or
    0= if false unloop exit then
  loop l 0 byte@ [char] - <> l l j-size 1- byte@ [char] - <> and ;
\ An optional trailing dot, then 1-253 characters of LDH labels; the last
\ label is not all digits.
: domain-name? { host -- flag }
  host j-size 0> if host host j-size 1- byte@ [char] . = if host host j-size 1- upto to host then then
  host j-size 1 254 within 0= if false exit then
  host s" ." str j-split { labels }
  labels j-size 0 ?do labels i j-at label? 0= if false unloop exit then loop
  labels labels j-size 1- j-at all-digits? 0= ;
: octet? { o -- flag } o j-size 1 4 within o decimal? and if o digits 256 < else false then ;
: loopback? { host -- flag }
  host s" localhost" text= host s" [::1]" text= or if true exit then
  host s" ." str j-split { parts }
  parts j-size 4 <> if false exit then
  parts 0 j-at s" 127" text= 0= if false exit then
  4 0 ?do parts i j-at octet? 0= if false unloop exit then loop true ;
\ The lowercase host of host[:port] or [literal][:port], or 0 if the
\ authority has userinfo or a bad port.
: authority-host { auth -- host|0 }
  0 0 -1 { host port at }
  auth [char] @ index-of 0>= if 0 exit then
  auth s" [" starts? if
    auth [char] ] index-of to at
    at 0< if 0 exit then
    auth at 1+ upto to host
    auth at 1+ from to port
    port j-size if
      port 0 byte@ [char] : <> if 0 exit then port 1 from to port
    else 0 to port then
  else
    auth [char] : index-of to at
    at 0>= if auth at upto to host auth at 1+ from to port else auth to host then
  then
  port if
    port j-size 1 6 within 0= if 0 exit then
    port all-digits? 0= if 0 exit then
    port digits 65535 > if 0 exit then
  then host lower ;
\ Section 3.1 step 4: a decoded segment is not . or .. and has no / \ or NUL.
: segment? { seg -- flag }
  seg percent-decode { d }
  d 0= if false exit then
  d s" ." text= d s" .." text= or if false exit then
  d s\" /\\\x00" index-of-any 0< ;
: path? { path -- flag }
  path segments { parts }
  parts j-size 0 ?do parts i j-at segment? 0= if false unloop exit then loop true ;
: kind-name ( kind -- string )
  case 1 of s" web" endof 2 of s" loopback" endof 3 of s" file" endof s" other" rot endcase str ;
\ Checks a srcLog or srcWitness reference (section 3.1). Returns its kind,
\ 1 web, 2 loopback, 3 file or 4 other, or 0 if it is invalid.
: reference-kind { ref -- kind }
  0 0 0 0 0 0 { colon scheme rest end host path }
  ref str? 0= if 0 exit then
  ref printable? 0= if 0 exit then
  ref [char] # index-of 0>= if 0 exit then
  ref scheme-end to colon colon 0< if 0 exit then
  ref colon upto lower to scheme ref colon 1+ from to rest
  scheme s" https" text= scheme s" http" text= or if
    rest s" //" starts? 0= if 0 exit then
    rest 2 from to rest
    rest s" /?" index-of-any dup 0< if drop rest j-size then to end
    rest end upto authority-host to host
    host 0= if 0 exit then
    rest [char] ? index-of dup 0< if drop rest j-size then { query }
    rest end query end - j-slice to path
    scheme s" https" text= if host domain-name? else host loopback? then 0= if 0 exit then
    path j-size 0= if 0 exit then
    path path? 0= if 0 exit then
    scheme s" https" text= if 1 else 2 then exit
  then
  scheme s" file" text= if
    rest [char] ? index-of 0>= if 0 exit then
    rest s" //" starts? if
      rest 2 from [char] / index-of dup 0< if drop 0 exit then 2 + to end
      rest 2 end 2 - j-slice to host
      host j-size 0<> host lower s" localhost" text= 0= and if 0 exit then
      rest end from to path
    else
      rest s" /" starts? 0= if 0 exit then rest to path
    then
    path path? if 3 else 0 then exit
  then
  rest j-size 0> if 4 else 0 then ;

\ Section 3.2 step 5: non-empty, passes section 3.1, and doesn't start or
\ end with White_Space once decoded.
: src-segment? { seg -- flag }
  seg j-size 0= if false exit then
  seg segment? 0= if false exit then
  seg percent-decode { d }
  d 0 utf8-at drop white-space? 0= d last-code-point white-space? 0= and ;
\ Derives srcLog and srcWitness from a percent-decoded src DID URL parameter
\ (section 3.2), or 0 0 if it is invalid.
: src-references { src -- log witness }
  0 0 0 0 0 { colon scheme rest end parts }
  src str? 0= if 0 0 exit then
  src printable? 0= if 0 0 exit then
  src s" ?#" index-of-any 0>= if 0 0 exit then
  src scheme-end to colon colon 0< if 0 0 exit then
  src colon upto lower to scheme src colon 1+ from to rest
  scheme s" http" text= scheme s" file" text= or if 0 0 exit then
  rest s" //" starts? 0= if 0 0 exit then
  rest rest j-size 1- byte@ [char] / = if rest rest j-size 1- upto to rest then
  rest j-size 2 > if
    rest 2 from [char] / index-of dup 0< if drop rest j-size else 2 + then
  else rest j-size then to end
  end 2 <= if 0 0 exit then
  scheme s" https" text= if
    rest 2 end 2 - j-slice authority-host { host }
    host 0= if 0 0 exit then
    host domain-name? 0= if 0 0 exit then
    end rest j-size < if
      rest end from segments to parts
      parts j-size 0 ?do parts i j-at src-segment? 0= if 0 0 unloop exit then loop
    then
  then
  scheme s" :" str j-cat rest j-cat { base }
  base s" /did.jsonl" str j-cat base s" /did-witness.json" str j-cat ;

\ ------------------------------------------------------------ DID URLs (section 4)

: invalid ( addr len -- result )
  j-object { r } false j-bool r s" valid" put str r s" error" put r ;
: reserved-option? { name -- flag }
  name s" didLog" text= name s" didWitness" text= or name s" srcLog" text= or
  name s" srcWitness" text= or name s" checkWatchers" text= or
  name s" extraWatchers" text= or name s" minCopies" text= or name s" includeDidLog" text= or 0<> ;
: used-parameter? { name -- flag }
  name s" src" text= name s" versionId" text= or name s" versionTime" text= or
  name s" versionNumber" text= or 0<> ;
: version-number? { v -- flag }
  v j-size 1 17 within v decimal? and if v 0 byte@ [char] 0 <> else false then ;
: number-of { s -- json }
  0 s j-size 0 ?do 10 * s i byte@ [char] 0 - + loop j-number ;
\ Dereferences a did:vh DID URL into {valid, did, options, fragment?}.
: parse-did-url { url -- result }
  0 0 0 0 0 0 0 0 0 0 { hash before q did options seen parts part name value }
  url str? 0= if s" invalidDidUrl" invalid exit then
  url [char] # index-of to hash
  hash 0< if url else url hash upto then to before
  before [char] ? index-of to q
  q 0< if before else before q upto then to did
  did did-scid-of 0= if s" invalidDidUrl" invalid exit then
  j-object to options j-array to seen
  q 0>= if
    before q 1+ from s" &" str j-split to parts
    parts j-size 0 ?do
      parts i j-at to part
      part [char] = index-of { eq }
      eq 0< if s" invalidDidUrl" invalid unloop exit then
      part eq upto percent-decode to name
      part eq 1+ from percent-decode to value
      name 0= value 0= or if s" invalidDidUrl" invalid unloop exit then
      name reserved-option? if s" invalidDidUrl" invalid unloop exit then
      name used-parameter? if
        seen name contains? if s" invalidDidUrl" invalid unloop exit then
        seen name j-push
        name s" src" text= if
          value src-references { log witness }
          log 0= if s" invalidDidUrl" invalid unloop exit then
          log options s" srcLog" put witness options s" srcWitness" put
        else name s" versionNumber" text= if
          value version-number? 0= if s" invalidDidUrl" invalid unloop exit then
          value number-of options s" versionNumber" put
        else
          value options name raw put
        then then
      then
    loop
  then
  j-object { r } true j-bool r s" valid" put did r s" did" put options r s" options" put
  hash 0>= if url hash 1+ from r s" fragment" put then r ;

\ ------------------------------------------------------------ resolution (section 5)

: did-error { vhlog addr len detail -- result }
  j-object { pd } addr len str pd s" title" put detail pd s" detail" put
  vhlog if vhlog pd s" vhLog" put then
  j-object { md } addr len str md s" error" put pd md s" problemDetails" put
  j-object { r } md r s" didResolutionMetadata" put 0 r s" didDocument" put
  j-object r s" didDocumentMetadata" put r ;
: fail { addr len -- result } 0 addr len addr len str did-error ;
: integer-at-least? { v min -- flag }
  v num? 0= if false exit then v j-integral 0= if false exit then v j-integer min >= ;
variable did-remote
: reference-option? { o addr len -- flag }
  o addr len j-has 0= if true exit then
  o addr len j-get reference-kind { kind }
  kind 0= if false exit then
  did-remote @ kind 2 = kind 3 = or and 0= ;
: extra-watchers? { w -- flag }
  w arr? 0= if false exit then
  w j-size 0 ?do
    w i j-at { u } u str? 0= if false unloop exit then
    u s" https://" starts? 0= if false unloop exit then
    u url? 0= if false unloop exit then
  loop true ;
\ Section 5 step 2.
: did-options? { o -- flag }
  o obj? 0= if false exit then
  o s" didLog" j-has 0<> o s" srcLog" j-has 0<> = if false exit then
  o s" didWitness" j-has o s" srcWitness" j-has and if false exit then
  o s" didLog" j-has if o s" didLog" j-get str? 0= if false exit then then
  o s" didWitness" j-has if o s" didWitness" j-get arr? 0= if false exit then then
  o s" srcLog" reference-option? 0= if false exit then
  o s" srcWitness" reference-option? 0= if false exit then
  o s" versionId" j-has 0<> o s" versionTime" j-has 0<> + o s" versionNumber" j-has 0<> + -1 < if false exit then
  o s" versionId" j-has if o s" versionId" j-get str? 0= if false exit then then
  o s" versionTime" j-has if o s" versionTime" j-get timestamp 0< if false exit then then
  o s" versionNumber" j-has if o s" versionNumber" j-get 1 integer-at-least? 0= if false exit then then
  o s" checkWatchers" j-has if
    o s" checkWatchers" j-get dup s" all" text= 0<> swap 0 integer-at-least? or 0= if false exit then
  then
  o s" extraWatchers" j-has if o s" extraWatchers" j-get extra-watchers? 0= if false exit then then
  o s" minCopies" j-has if o s" minCopies" j-get 1 integer-at-least? 0= if false exit then then
  o s" includeDidLog" j-has if o s" includeDidLog" j-get bool? 0= if false exit then then
  true ;
\ Section 5 step 3.
: offline-unsupported? { o -- flag }
  o s" srcLog" j-has if true exit then
  o s" checkWatchers" j-has if
    o s" checkWatchers" j-get dup num? 0= swap j-integer 0<> or if true exit then
  then
  o s" extraWatchers" j-has if o s" extraWatchers" j-get j-size 0> if true exit then then
  false ;
\ True if some entry among the first N sets a non-empty witness list.
: needs-witnessing? { entries n -- flag }
  n 0 ?do
    entries i j-at s" parameters" j-get s" witness" j-get { w }
    w obj? w j-size 0> and if true unloop exit then
  loop false ;
: did-code ( code -- addr len )
  dup s" not-found" text= if drop s" notFound" exit then
  dup s" invalid-option" text= if drop s" invalidOptions" exit then
  dup s" unsupported-log-version" text= if drop s" featureNotSupported" exit then
  dup s" fork-detected" text= if drop s" logForked" exit then
  s" min-copies-not-met" text= if s" insufficientCopies" exit then
  s" invalidDid" ;
: vh-request { o now -- input }
  j-object { input } j-object { vo }
  o s" didLog" j-get input s" log" put now input s" now" put
  o s" didWitness" j-has if o s" didWitness" j-get input s" witness" put then
  o s" versionId" j-has if o s" versionId" j-get vo s" versionId" put then
  o s" versionTime" j-has if o s" versionTime" j-get vo s" versionTime" put then
  o s" versionNumber" j-has if o s" versionNumber" j-get vo s" versionNumber" put then
  o s" minCopies" j-has if o s" minCopies" j-get vo s" minCopies" put then
  vo input s" options" put input ;
: copy-into { from to addr len -- } from addr len j-get to addr len put ;
\ Resolves a did:vh DID offline (section 5) from a didvh-resolve input
\ {did, options, now, remote?}.
: resolve-did { input -- result }
  input s" options" j-get { o }
  input s" did" j-get did-scid-of { scid }
  scid 0= if s" invalidDid" fail exit then
  input s" remote" j-get j-truth did-remote !
  o did-options? 0= if s" invalidOptions" fail exit then
  o offline-unsupported? if s" featureNotSupported" fail exit then
  o s" didLog" j-get { text } text entries-from-log { entries }
  o s" srcWitness" j-has entries entries j-size needs-witnessing? and if s" featureNotSupported" fail exit then
  o input s" now" j-get vh-request { request }
  scid did-scid ! did-specialisation
  request ['] resolve-log catch vh-log-specialisation 0 did-scid ! throw { result }
  result s" error" j-get { error }
  result s" valid" j-get j-truth 0= if
    error error s" code" j-get did-code error s" message" j-get did-error exit
  then
  o s" versionId" j-has o s" versionTime" j-has or o s" versionNumber" j-has or 0=
  error s" code" j-get s" unsupported-log-version" text= and if
    error s" featureNotSupported" error s" message" j-get did-error exit
  then
  result s" metadata" j-get { meta }
  result s" firstInvalidVersion" j-get dup num? if j-integer 1- else drop entries j-size then { valid }
  j-object { rm } s" application/did+json" str rm s" contentType" put
  meta s" warnings" j-get dup j-size 0> if rm s" warnings" put else drop then
  o s" includeDidLog" j-get j-truth if
    text 10 char$ j-split { lines } empty$ { log }
    valid 0 ?do log lines i j-at j-cat 10 char$ j-cat to log loop
    log rm s" didLog" put
    entries valid needs-witnessing? if
      o s" didWitness" j-has if o s" didWitness" j-get else j-array then rm s" didWitness" put
    then
  then
  j-object { dm }
  meta dm s" versionId" copy-into meta dm s" versionTime" copy-into
  meta dm s" created" copy-into meta dm s" updated" copy-into
  meta dm s" scid" copy-into meta dm s" deactivated" copy-into meta dm s" ttl" copy-into
  meta s" witness" j-get obj? if meta dm s" witness" copy-into then
  meta dm s" watchers" copy-into
  j-object { r } rm r s" didResolutionMetadata" put
  meta s" deactivated" j-get j-truth meta s" versionNumber" j-get j-integer valid = and
  if 0 else result s" state" j-get then r s" didDocument" put
  dm r s" didDocumentMetadata" put r ;

\ ------------------------------------------------------------ driver results

: reference-result ( input -- result )
  s" ref" j-get reference-kind { kind }
  kind 0= if s" invalidOptions" invalid exit then
  j-object { r } true j-bool r s" valid" put kind kind-name r s" kind" put r ;
: src-result ( input -- result )
  s" src" j-get src-references { log witness }
  log 0= if s" invalidDidUrl" invalid exit then
  j-object { r } true j-bool r s" valid" put log r s" srcLog" put witness r s" srcWitness" put r ;
