require native.fs
\ JSON handles are request-scoped, including strings containing binary bytes.
: str ( addr len -- json ) j-string ;
: raw ( json -- addr len ) dup j-data swap j-size ;
: json-parse ( string -- json|0 ) raw j-parse ;
: put { value object addr len -- } object addr len value j-set ;
: field= { object addr len expected -- flag } object addr len j-get expected j-equal ;
: text= ( json addr len -- flag ) str j-equal ;
: obj? ( json -- flag ) j-type 5 = ;
: arr? ( json -- flag ) j-type 4 = ;
: str? ( json -- flag ) j-type 3 = ;
: num? ( json -- flag ) j-type 2 = ;
: bool? ( json -- flag ) j-type 1 = ;
: empty$ ( -- string ) s" " str ;
: char$ ( char -- string ) pad c! pad 1 str ;
: integer$ ( n -- string ) 0 <# #s #> str ;
: contains? { array value -- flag }
  array j-size 0 ?do array i j-at value j-equal if true unloop exit then loop false ;
: merge { base delta -- object }
  base j-clone { result } delta j-keys { keys }
  keys j-size 0 ?do keys i j-at raw { a n }
    delta a n j-get result a n put loop result ;
: without-proof ( object -- object ) j-clone dup s" proof" j-del ;
: jcs { value -- string }
  value j-type 2 = if value j-decimal exit then
  value arr? if
    s" [" str { out }
    value j-size 0 ?do
      i if out s" ," str j-cat to out then
      out value i j-at recurse j-cat to out
    loop out s" ]" str j-cat exit
  then
  value obj? if
    value j-keys { keys } keys j-size { n }
    n cells allocate throw { sorted }
    n 0 ?do keys i j-at sorted i cells + ! loop
    n 0 ?do n i 1+ ?do
      sorted j cells + @ sorted i cells + @ j-utf16cmp 0> if
        sorted j cells + @ sorted i cells + @
        sorted j cells + ! sorted i cells + !
      then loop loop
    s" {" str { out }
    n 0 ?do
      i if out s" ," str j-cat to out then
      sorted i cells + @ { key }
      out key j-dump j-cat s" :" str j-cat
      value key raw j-get recurse j-cat to out
    loop sorted free throw out s" }" str j-cat exit
  then value j-dump ;
